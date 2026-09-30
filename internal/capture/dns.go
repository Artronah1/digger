package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- Константы ---

const (
	dnsTableMaxAge  = 5 * time.Minute  // окно показа запросов (DNSTable)
	dnsMapMaxAge    = 2 * time.Minute  // окно актуальности связок (DNSMapping)
	dnsFallbackTTL  = 10 * time.Minute // TTL=0 → считаем столько
	obsPerPairMax   = 16               // записей истории на пару (name, IP)
	obsHistoryDepth = 1 * time.Hour    // глубина истории наблюдений

	retryWindow      = time.Second // ретраи внутри окна не считаем отдельно
	dnsSweepInterval = time.Minute // период уборки (DNSMapping)
)

// --- DNSTable ---

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
	Flags     string // метки аномалий

	// Дедупликация ретраев.
	lastCounted time.Time
}

// DNSTable — таблица наблюдённых DNS-запросов.
type DNSTable struct {
	mu      sync.Mutex
	queries map[string]*DNSQuery
	maxAge  time.Duration
	showPTR bool
}

func NewDNSTable() *DNSTable {
	return &DNSTable{
		queries: make(map[string]*DNSQuery),
		maxAge:  dnsTableMaxAge,
	}
}

// SetMaxAge задаёт максимальный возраст записи для отображения.
func (dt *DNSTable) SetMaxAge(d time.Duration) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.maxAge = d
}

// SetShowPTR включает/выключает показ PTR-запросов.
func (dt *DNSTable) SetShowPTR(v bool) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.showPTR = v
}

// Update разбирает payload и, если это DNS-запрос, добавляет в таблицу.
func (dt *DNSTable) Update(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, proto string) {
	msg := dnsMessage(payload, proto)
	if msg == nil {
		return
	}

	name, qtype, ok := parseDNSQuery(msg)
	if !ok {
		return
	}

	transport := dnsTransport(proto, srcPort, dstPort)
	key := name + "|" + qtype + "|" + srcIP + "|" + dstIP + "|" + transport
	now := time.Now()

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
			FirstSeen: now,
		}
		dt.queries[key] = q
	}

	// Ретраи того же запроса в течение retryWindow не считаем.
	if q.lastCounted.IsZero() || now.Sub(q.lastCounted) >= retryWindow {
		q.Count++
		q.lastCounted = now
	}
	q.LastSeen = now
}

// SetFlags устанавливает метку аномалии для запроса.
// Транспорт в ключе НЕ участвует: раньше ключ был захардкожен с "udp/53",
// и метки терялись для mDNS и TCP/53.
func (dt *DNSTable) SetFlags(name, qtype, srcIP, dstIP, flags string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	for _, q := range dt.queries {
		if q.Name != name || q.QType != qtype || q.SrcIP != srcIP || q.DstIP != dstIP {
			continue
		}
		if q.Flags == "" {
			q.Flags = flags
			continue
		}
		// Точное совпадение токена: substring-проверка ловила
		// "⚠POLICY-DNS→8.8.8.8" внутри "...→8.8.8.81".
		if !slices.Contains(strings.Fields(q.Flags), flags) {
			q.Flags += " " + flags
		}
	}
}

// Snapshot возвращает копию записей, свежие сверху.
// Попутно чистит записи старше окна показа: без этого таблица
// растёт бесконечно (метки приходят сразу после запроса, запаздывания нет).
func (dt *DNSTable) Snapshot() []DNSQuery {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	if dt.maxAge > 0 {
		cutoff := time.Now().Add(-dt.maxAge).Add(-time.Minute) // запас для SetFlags
		for key, q := range dt.queries {
			if q.LastSeen.Before(cutoff) {
				delete(dt.queries, key)
			}
		}
	}

	out := make([]DNSQuery, 0, len(dt.queries))
	for _, q := range dt.queries {
		out = append(out, *q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
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

	dt.mu.Lock()
	maxAge := dt.maxAge
	showPTR := dt.showPTR
	dt.mu.Unlock()

	// Фильтр по свежести и PTR.
	cutoff := time.Now().Add(-maxAge)
	queries := make([]DNSQuery, 0, len(all))
	for _, q := range all {
		if maxAge > 0 && !q.LastSeen.After(cutoff) {
			continue
		}
		if !showPTR && isReverseDNSName(q.Name) {
			continue
		}
		queries = append(queries, q)
	}
	if len(queries) == 0 {
		return
	}

	fmt.Printf("\n=== DNS-запросы (%d) ===\n", len(queries))

	// Запросы к внешним резолверам. mDNS — multicast (224.0.0.251 / ff02::fb),
	// он не «внешний DNS», хотя IP не приватный.
	external := 0
	for _, q := range queries {
		if q.Transport != "mdns" && !isPrivateIP(q.DstIP) {
			external++
		}
	}
	if external > 0 {
		fmt.Printf("⚠  обнаружены запросы к внешним DNS: %d\n", external)
	}

	fmt.Printf("%-18s %-40s %-6s %-8s %-16s %5s %-5s %s\n",
		"SRC", "NAME", "QTYPE", "VIA", "TO", "COUNT", "AGE", "FLAGS")

	for _, q := range queries {
		age := time.Since(q.FirstSeen).Truncate(time.Second)
		fmt.Printf("%-18s %-40s %-6s %-8s %-16s %5d %-5s %s\n",
			truncate(q.SrcIP, 18),
			truncate(q.Name, 40),
			q.QType,
			q.Transport,
			truncate(q.DstIP, 16),
			q.Count,
			age.String(),
			q.Flags)
	}
	fmt.Println()
}

// --- Разбор DNS ---

// dnsMessage извлекает DNS-сообщение из payload пакета.
// DNS-over-TCP предваряет сообщение двухбайтовой длиной — раньше её
// не снимали, и TCP/53 парсился мимо (заголовок читался со смещением).
func dnsMessage(payload []byte, proto string) []byte {
	if len(payload) < 12 {
		return nil
	}
	if proto != protoTCP {
		return payload
	}
	if len(payload) < 14 {
		return nil
	}
	// Длина должна совпадать: продолжения сегментов и мусор отбрасываем —
	// парсинг всё равно не прошёл бы.
	if n := binary.BigEndian.Uint16(payload[:2]); int(n) != len(payload)-2 {
		return nil
	}
	return payload[2:]
}

// dnsTransport — человекочитаемый транспорт DNS-пакета.
func dnsTransport(proto string, srcPort, dstPort uint16) string {
	switch proto {
	case protoTCP:
		return "tcp/53" // DNS-over-TCP — только 53
	case protoUDP:
		switch {
		case srcPort == portMDNS || dstPort == portMDNS:
			return "mdns"
		case dstPort == portDNS:
			return "udp/53"
		default:
			return fmt.Sprintf("udp/%d", dstPort)
		}
	default:
		return proto
	}
}

// readName читает доменное имя с позиции pos.
// Указатель компрессии завершает имя (не разворачиваем — для наших
// задач достаточно). Возвращает имя, новую позицию и признак успеха.
func readName(msg []byte, pos int) (string, int, bool) {
	if pos >= len(msg) {
		return "", 0, false
	}
	var b strings.Builder
	for pos < len(msg) {
		l := int(msg[pos])
		switch {
		case l == 0: // конец имени
			return b.String(), pos + 1, true
		case l&0xC0 == 0xC0: // указатель компрессии
			if pos+2 > len(msg) {
				return "", 0, false
			}
			return b.String(), pos + 2, true
		case l&0xC0 != 0: // зарезервированные биты — мусор
			return "", 0, false
		}
		pos++
		if pos+l > len(msg) {
			return "", 0, false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[pos : pos+l])
		pos += l
	}
	return "", 0, false
}

// skipName пропускает доменное имя (секция ответов: имя не нужно).
// Возвращает новую позицию или -1. Прежний код после компрессии
// в середине имени съедал лишний байт и читал TYPE со смещением.
func skipName(msg []byte, pos int) int {
	for pos < len(msg) {
		l := int(msg[pos])
		switch {
		case l == 0:
			return pos + 1
		case l&0xC0 == 0xC0:
			if pos+2 > len(msg) {
				return -1
			}
			return pos + 2
		case l&0xC0 != 0:
			return -1
		}
		pos += 1 + l
	}
	return -1
}

// parseDNSQuery разбирает DNS-запрос: (qname, qtype, true).
func parseDNSQuery(msg []byte) (string, string, bool) {
	if len(msg) < 12 {
		return "", "", false
	}
	// QR=0 — запрос; QDCOUNT=1.
	if flags := binary.BigEndian.Uint16(msg[2:4]); flags&0x8000 != 0 {
		return "", "", false
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return "", "", false
	}

	name, pos, ok := readName(msg, 12)
	if !ok || pos+2 > len(msg) {
		return "", "", false
	}
	return name, dnsTypeString(binary.BigEndian.Uint16(msg[pos : pos+2])), true
}

// parseDNSResponse разбирает DNS-ответ: записи A/AAAA + минимальный TTL.
// Возвращает (qname, IP, minTTL, ok). Прежние parseDNSResponse и
// parseDNSResponseTTL были копипастой и парсили каждый ответ дважды.
func parseDNSResponse(msg []byte) (string, []string, uint32, bool) {
	if len(msg) < 12 {
		return "", nil, 0, false
	}
	if flags := binary.BigEndian.Uint16(msg[2:4]); flags&0x8000 == 0 {
		return "", nil, 0, false // это запрос
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	if qdcount == 0 || ancount == 0 {
		return "", nil, 0, false
	}

	// Секция вопроса: QNAME + QTYPE(2) + QCLASS(2).
	name, pos, ok := readName(msg, 12)
	if !ok || name == "" {
		return "", nil, 0, false
	}
	pos += 4

	var ips []string
	var minTTL uint32

	for i := 0; i < int(ancount); i++ {
		pos = skipName(msg, pos) // владелец записи — пропускаем
		if pos < 0 {
			break
		}
		// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
		if pos+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[pos : pos+2])
		ttl := binary.BigEndian.Uint32(msg[pos+4 : pos+8])
		rdlength := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10
		if pos+rdlength > len(msg) {
			break
		}

		switch rtype {
		case 1: // A
			if rdlength == 4 {
				ips = append(ips, net.IP(msg[pos:pos+4]).String())
				if minTTL == 0 || ttl < minTTL {
					minTTL = ttl
				}
			}
		case 28: // AAAA
			if rdlength == 16 {
				ips = append(ips, net.IP(msg[pos:pos+16]).String())
				if minTTL == 0 || ttl < minTTL {
					minTTL = ttl
				}
			}
		}
		pos += rdlength
	}

	if len(ips) == 0 {
		return "", nil, 0, false
	}
	return name, ips, minTTL, true
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

// isReverseDNSName: PTR-запросы (reverse-зона).
func isReverseDNSName(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa") ||
		strings.HasSuffix(name, ".ip6.arpa")
}

// isPrivateIP — приватный/локальный адрес.
// Похоже на дубликат isLANIP из capture.go (и хуже: "::1" не loopback) —
// оставлен как делегат; в итоге стоит оставить одно имя.
func isPrivateIP(ip string) bool {
	return isLANIP(ip)
}

// --- DNSMapping ---

// DNSMapping — хранилище связей name ↔ IP. Две структуры:
//   - nameToIPs/ipToNames — «текущий срез»: кто во что резолвится сейчас;
//   - observations — история наблюдений с TTL: кто резолвился КОГДА.
type DNSMapping struct {
	mu        sync.RWMutex
	nameToIPs map[string]map[string]time.Time // name → IP → lastSeen
	ipToNames map[string]map[string]time.Time // IP → name → lastSeen
	maxAge    time.Duration

	observations map[string][]DNSObservation // key = name + "|" + ip

	lastSweep time.Time
}

// DNSObservation — одно наблюдение DNS-ответа.
type DNSObservation struct {
	QName      string
	QType      string
	Answers    []string
	ObservedAt time.Time
	ExpiresAt  time.Time
	ClientIP   string
	ResolverIP string
	Transport  string
	TTL        uint32
}

func NewDNSMapping() *DNSMapping {
	return &DNSMapping{
		nameToIPs:    make(map[string]map[string]time.Time),
		ipToNames:    make(map[string]map[string]time.Time),
		maxAge:       dnsMapMaxAge,
		observations: make(map[string][]DNSObservation),
	}
}

// Update обрабатывает DNS-ответ: пополняет историю наблюдений и текущие
// связки. srcIP/dstIP — клиент и резолвер соответственно.
func (m *DNSMapping) Update(payload []byte, srcIP, dstIP, proto string) {
	msg := dnsMessage(payload, proto)
	if msg == nil {
		return
	}

	name, ips, ttl, ok := parseDNSResponse(msg)
	if !ok {
		return
	}

	transport := "udp/53"
	if proto == protoTCP {
		transport = "tcp/53"
	}

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.addObservationLocked(DNSObservation{
		QName:      name,
		Answers:    ips,
		ObservedAt: now,
		TTL:        ttl,
		ClientIP:   srcIP,
		ResolverIP: dstIP,
		Transport:  transport,
	})
	for _, ip := range ips {
		m.addLocked(name, ip, now)
	}
	m.maybeSweepLocked(now)
}

// Add добавляет связь name → IP (обновляет lastSeen).
func (m *DNSMapping) Add(name, ip string) {
	if name == "" || ip == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addLocked(name, ip, time.Now())
}

func (m *DNSMapping) addLocked(name, ip string, now time.Time) {
	if m.nameToIPs[name] == nil {
		m.nameToIPs[name] = make(map[string]time.Time)
	}
	m.nameToIPs[name][ip] = now

	if m.ipToNames[ip] == nil {
		m.ipToNames[ip] = make(map[string]time.Time)
	}
	m.ipToNames[ip][name] = now
}

// AddObservation добавляет наблюдение DNS-ответа.
func (m *DNSMapping) AddObservation(obs DNSObservation) {
	if obs.QName == "" || len(obs.Answers) == 0 {
		return
	}
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.addObservationLocked(obs)
}

func (m *DNSMapping) addObservationLocked(obs DNSObservation) {
	if obs.ExpiresAt.IsZero() {
		ttl := dnsFallbackTTL
		if obs.TTL > 0 {
			ttl = time.Duration(obs.TTL) * time.Second
		}
		obs.ExpiresAt = obs.ObservedAt.Add(ttl)
	}

	for _, ip := range obs.Answers {
		key := obs.QName + "|" + ip
		list := append(m.observations[key], obs)
		if len(list) > obsPerPairMax { // история на пару ограничена
			list = list[len(list)-obsPerPairMax:]
		}
		m.observations[key] = list
	}
}

// maybeSweepLocked — периодическая уборка: без неё maps растут бесконечно.
func (m *DNSMapping) maybeSweepLocked(now time.Time) {
	if now.Sub(m.lastSweep) < dnsSweepInterval {
		return
	}
	m.lastSweep = now

	// Текущий срез: читатели и так фильтруют по maxAge — освобождаем память.
	cutoff := now.Add(-m.maxAge)
	for name, ips := range m.nameToIPs {
		for ip, t := range ips {
			if t.Before(cutoff) {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(m.nameToIPs, name)
		}
	}
	for ip, names := range m.ipToNames {
		for name, t := range names {
			if t.Before(cutoff) {
				delete(names, name)
			}
		}
		if len(names) == 0 {
			delete(m.ipToNames, ip)
		}
	}

	// История: глубина obsHistoryDepth — старше NamesForIPAt не отвечает.
	obsCutoff := now.Add(-obsHistoryDepth)
	for key, list := range m.observations {
		n := 0
		for _, o := range list {
			if o.ObservedAt.After(obsCutoff) {
				list[n] = o
				n++
			}
		}
		if n == 0 {
			delete(m.observations, key)
		} else {
			m.observations[key] = list[:n]
		}
	}
}

// SnapshotObservations возвращает все наблюдения DNS.
func (m *DNSMapping) SnapshotObservations() []DNSObservation {
	return m.SnapshotObservationsSince(time.Time{})
}

// SnapshotObservationsSince — наблюдения с ObservedAt >= cutoff.
func (m *DNSMapping) SnapshotObservationsSince(cutoff time.Time) []DNSObservation {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]DNSObservation, 0)
	seen := make(map[string]bool)
	for _, list := range m.observations {
		for _, o := range list {
			if o.ObservedAt.Before(cutoff) {
				continue
			}
			// Одно наблюдение лежит под несколькими ключами (по каждому IP
			// из Answers) — дедуп по (qname, время).
			key := o.QName + "|" + o.ObservedAt.Format(time.RFC3339Nano)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, o)
		}
	}
	return out
}

// NamesForIPAt возвращает имена, чьи наблюдения были актуальны на момент at.
// O(размер истории): при частых вызовах стоит добавить обратный индекс.
func (m *DNSMapping) NamesForIPAt(ip string, at time.Time) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make(map[string]bool)
	for key, obsList := range m.observations {
		name, obsIP, ok := splitObsKey(key)
		if !ok || obsIP != ip {
			continue
		}
		for _, o := range obsList {
			if o.ObservedAt.After(at) {
				continue // наблюдение позже интересующего момента
			}
			if !o.ExpiresAt.IsZero() && o.ExpiresAt.Before(at) {
				continue // к моменту at уже истекло
			}
			names[name] = true
			break
		}
	}

	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	return out
}

func splitObsKey(key string) (name, ip string, ok bool) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '|' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

// IPsForName возвращает IP, в которые резолвился name за последнее время.
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

// NamesForIP возвращает имена, которые резолвились в этот IP.
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

// Len возвращает число известных пар name → IP.
func (m *DNSMapping) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ipToNames)
}
