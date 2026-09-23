package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSQuery — одна наблюдённая DNS-запись.
type DNSQuery struct {
	Name      string
	QType     string
	SrcIP     string
	DstIP     string
	Transport string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     uint64

	// Для дедупликации retry'ев
	lastCounted time.Time
}

// DNSTable — таблица наблюдённых DNS-запросов.
type DNSTable struct {
	mu       sync.Mutex
	queries  map[string]*DNSQuery
	maxAge   time.Duration // если > 0, старые записи не печатаются
}

func NewDNSTable() *DNSTable {
	return &DNSTable{
		queries: make(map[string]*DNSQuery),
		maxAge:  5 * time.Minute, // по умолчанию — показываем записи за 5 минут
	}
}

// SetMaxAge задаёт максимальный возраст записи для отображения.
func (dt *DNSTable) SetMaxAge(d time.Duration) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.maxAge = d
}

// Update разбирает payload и, если это DNS-запрос, добавляет в таблицу.
func (dt *DNSTable) Update(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, proto string) {
	name, qtype, ok := parseDNSQuery(payload)
	if !ok {
		return
	}

	transport := proto
	switch {
		case proto == "UDP" && srcPort == 5353:
			transport = "mdns"
		case proto == "UDP" && dstPort == 5353:
			transport = "mdns"
		case proto == "UDP" && dstPort == 53:
			transport = "udp/53"
		case proto == "UDP":
			transport = fmt.Sprintf("udp/%d", dstPort)
		case proto == "TCP" && dstPort == 53:
			transport = "tcp/53"
	}

	key := name + "|" + qtype + "|" + srcIP + "|" + dstIP + "|" + transport

	dt.mu.Lock()
	defer dt.mu.Unlock()

	q, ok := dt.queries[key]
	if !ok {
		q = &DNSQuery{
			Name:      name,
			QType:     qtype,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Transport: transport,
			FirstSeen: time.Now(),
		}
		dt.queries[key] = q
	}
	now := time.Now()

	// Дедупликация: если тот же запрос пришёл < 1 сек назад — это retry, не считаем
	if q.lastCounted.IsZero() || now.Sub(q.lastCounted) >= time.Second {
		q.Count++
		q.lastCounted = now
	}

	q.LastSeen = now
}

// Snapshot возвращает копию записей, отсортированную по LastSeen.
func (dt *DNSTable) Snapshot() []DNSQuery {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	out := make([]DNSQuery, 0, len(dt.queries))
	for _, q := range dt.queries {
		out = append(out, *q)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// Len возвращает число уникальных записей.
func (dt *DNSTable) Len() int {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	return len(dt.queries)
}

// Print выводит таблицу DNS-запросов.
func (dt *DNSTable) Print() {
	all := dt.Snapshot()
	if len(all) == 0 {
		return
	}

	// Фильтр по свежести
	dt.mu.Lock()
	maxAge := dt.maxAge
	dt.mu.Unlock()

	queries := all
	if maxAge > 0 {
		cutoff := time.Now().Add(-maxAge)
		queries = make([]DNSQuery, 0, len(all))
		for _, q := range all {
			if q.LastSeen.After(cutoff) {
				queries = append(queries, q)
			}
		}
	}

	if len(queries) == 0 {
		return
	}

	// Собираем уникальные DNS-серверы, к которым обращались
	dnsServers := make(map[string]int)
	for _, q := range queries {
		dnsServers[q.DstIP]++
	}

	fmt.Printf("\n=== DNS-запросы (%d) ===\n", len(queries))

	// Если запросов к внешним DNS много — предупреждаем
	externalCount := 0
	for ip, count := range dnsServers {
		if !isPrivateIP(ip) {
			externalCount += count
		}
	}
	if externalCount > 0 {
		fmt.Printf("⚠  обнаружены запросы к внешним DNS: %d\n", externalCount)
	}

	fmt.Printf("%-18s %-40s %-6s %-8s %-16s %5s %s\n",
		   "SRC", "NAME", "QTYPE", "VIA", "TO", "COUNT", "AGE")

	for _, q := range queries {
		age := time.Since(q.FirstSeen).Truncate(time.Second)
		fmt.Printf("%-18s %-40s %-6s %-8s %-16s %5d %s\n",
			   truncate(q.SrcIP, 18),
			   truncate(q.Name, 40),
			   q.QType,
	     q.Transport,
	     q.DstIP,
	     q.Count,
	     age.String())
	}
	fmt.Println()
}

// parseDNSQuery разбирает DNS-запрос из payload.
// Возвращает (qname, qtype, true) если это запрос.
func parseDNSQuery(payload []byte) (string, string, bool) {
	// Минимум: 12 байт заголовка + вопрос
	if len(payload) < 13 {
		return "", "", false
	}

	// Flags: QR bit (bit 15) = 0 для запроса, 1 для ответа
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 {
		return "", "", false // это ответ, не запрос
	}

	// QDCOUNT должен быть 1
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	if qdcount != 1 {
		return "", "", false
	}

	// Парсим QNAME начиная с offset 12
	pos := 12
	var name strings.Builder
	for pos < len(payload) {
		labelLen := int(payload[pos])
		if labelLen == 0 {
			pos++
			break
		}
		// Компрессия не должна быть в запросе (только в ответе)
		if labelLen&0xC0 != 0 {
			return "", "", false
		}
		pos++
		if pos+labelLen > len(payload) {
			return "", "", false
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(payload[pos : pos+labelLen])
		pos += labelLen
	}

	// QTYPE
	if pos+2 > len(payload) {
		return "", "", false
	}
	qtype := binary.BigEndian.Uint16(payload[pos : pos+2])

	qtypeStr := dnsTypeString(qtype)
	return name.String(), qtypeStr, true
}

// dnsTypeString возвращает человекочитаемое имя типа DNS-записи.
func dnsTypeString(t uint16) string {
	switch t {
		case 1:
			return "A"
		case 2:
			return "NS"
		case 5:
			return "CNAME"
		case 6:
			return "SOA"
		case 12:
			return "PTR"
		case 15:
			return "MX"
		case 16:
			return "TXT"
		case 28:
			return "AAAA"
		case 33:
			return "SRV"
		case 43:
			return "DS"
		case 46:
			return "RRSIG"
		case 47:
			return "NSEC"
		case 48:
			return "DNSKEY"
		case 65:
			return "HTTPS"
		case 255:
			return "ANY"
		default:
			return fmt.Sprintf("T%d", t)
	}
}

// parseDNSResponse разбирает DNS-ответ и возвращает (qname, []IP, true).
// Поддерживает записи A и AAAA.
func parseDNSResponse(payload []byte) (string, []string, bool) {
	if len(payload) < 12 {
		return "", nil, false
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return "", nil, false // это не ответ
	}

	qdcount := binary.BigEndian.Uint16(payload[4:6])
	ancount := binary.BigEndian.Uint16(payload[6:8])
	if qdcount == 0 || ancount == 0 {
		return "", nil, false
	}

	// Пропускаем QNAME
	pos := 12
	var qname strings.Builder
	for pos < len(payload) {
		labelLen := int(payload[pos])
		if labelLen == 0 {
			pos++
			break
		}
		if labelLen&0xC0 != 0 {
			// Компрессия в вопросе (редко, но бывает)
			pos += 2
			break
		}
		pos++
		if pos+labelLen > len(payload) {
			return "", nil, false
		}
		if qname.Len() > 0 {
			qname.WriteByte('.')
		}
		qname.Write(payload[pos : pos+labelLen])
		pos += labelLen
	}

	// QTYPE + QCLASS
	pos += 4

	name := qname.String()
	if name == "" {
		return "", nil, false
	}

	var ips []string

	// Парсим ответы
	for i := 0; i < int(ancount); i++ {
		// NAME в ответе — может быть сжатие
		if pos >= len(payload) {
			break
		}
		if payload[pos]&0xC0 == 0xC0 {
			pos += 2 // compressed name
		} else {
			for pos < len(payload) && payload[pos] != 0 {
				labelLen := int(payload[pos])
				if labelLen&0xC0 != 0 {
					pos += 2
					break
				}
				pos += 1 + labelLen
			}
			pos++ // null byte
		}

		if pos+10 > len(payload) {
			break
		}
		rtype := binary.BigEndian.Uint16(payload[pos : pos+2])
		rdlength := int(binary.BigEndian.Uint16(payload[pos+8 : pos+10]))
		pos += 10

		if pos+rdlength > len(payload) {
			break
		}

		switch rtype {
			case 1: // A
				if rdlength == 4 {
					ips = append(ips, fmt.Sprintf("%d.%d.%d.%d",
								      payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]))
				}
			case 28: // AAAA
				if rdlength == 16 {
					ip := net.IP(payload[pos : pos+16])
					ips = append(ips, ip.String())
				}
		}

		pos += rdlength
	}

	if len(ips) == 0 {
		return "", nil, false
	}
	return name, ips, true
}

// isPrivateIP — грубая проверка, что IP из приватного диапазона.
func isPrivateIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "169.254.") {
			return true
		}
		// 172.16.0.0/12
		if strings.HasPrefix(ip, "172.") {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				// второй октет 16..31
				switch parts[1] {
					case "16", "17", "18", "19", "20", "21", "22", "23",
					"24", "25", "26", "27", "28", "29", "30", "31":
					return true
				}
			}
		}
		// IPv6 link-local
		if strings.HasPrefix(ip, "fe80:") || strings.HasPrefix(ip, "fc") || strings.HasPrefix(ip, "fd") {
			return true
		}
		return false
}

// DNSMapping — хранилище связей name → IP и IP → name.
type DNSMapping struct {
	mu           sync.RWMutex
	nameToIPs    map[string]map[string]time.Time // name -> (IP -> lastSeen)
	ipToNames    map[string]map[string]time.Time // IP -> (name -> lastSeen)
	maxAge       time.Duration
}

func NewDNSMapping() *DNSMapping {
	return &DNSMapping{
		nameToIPs: make(map[string]map[string]time.Time),
		ipToNames: make(map[string]map[string]time.Time),
		maxAge:    2 * time.Minute,
	}
}

// Add добавляет связь name → IP.
func (m *DNSMapping) Add(name, ip string) {
	if name == "" || ip == "" {
		return
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nameToIPs[name] == nil {
		m.nameToIPs[name] = make(map[string]time.Time)
	}
	m.nameToIPs[name][ip] = now

	if m.ipToNames[ip] == nil {
		m.ipToNames[ip] = make(map[string]time.Time)
	}
	m.ipToNames[ip][name] = now
}

// IPsForName возвращает список IP, в которые резолвился name за последнее время.
func (m *DNSMapping) IPsForName(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ips, ok := m.nameToIPs[name]
	if !ok {
		return nil
	}
	cutoff := time.Now().Add(-m.maxAge)
	out := make([]string, 0, len(ips))
	for ip, t := range ips {
		if t.After(cutoff) {
			out = append(out, ip)
		}
	}
	return out
}

// NamesForIP возвращает список имён, которые резолвились в этот IP.
func (m *DNSMapping) NamesForIP(ip string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names, ok := m.ipToNames[ip]
	if !ok {
		return nil
	}
	cutoff := time.Now().Add(-m.maxAge)
	out := make([]string, 0, len(names))
	for name, t := range names {
		if t.After(cutoff) {
			out = append(out, name)
		}
	}
	return out
}

// Update обрабатывает DNS-ответ и добавляет связи.
func (m *DNSMapping) Update(payload []byte) {
	name, ips, ok := parseDNSResponse(payload)
	if !ok {
		return
	}
	for _, ip := range ips {
		m.Add(name, ip)
	}
}
