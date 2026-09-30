package capture

import (
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"digger/internal/baseline"
	"digger/internal/policy"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/huatuo-ai/go-pcap"
)

// --- Константы (были магическими числами) ---

const (
	portDNS   uint16 = 53   // DNS
	portMDNS  uint16 = 5353 // mDNS
	portHTTPS uint16 = 443  // TLS / QUIC

	protoTCP = "TCP"
	protoUDP = "UDP"

	printInterval  = 5 * time.Second // период вывода
	enrichInterval = 1 * time.Second // период enrichment

	anomalyWindow   = 5 * time.Minute // окно аномалий
	shortDebugLimit = 5               // сколько коротких пакетов показывать в verbose

	ethHeaderLen = 14 // минимальный Ethernet-кадр
)

// Capture — сессия захвата и анализа трафика.
type Capture struct {
	// --- Захват ---
	handle  *pcap.Handle
	iface   string
	filter  string
	snaplen int
	verbose bool

	// --- Жизненный цикл ---
	stopCh   chan struct{}
	stopOnce sync.Once

	// --- Состояние анализа ---
	flows      *FlowTable
	dnsTable   *DNSTable
	dnsMapping *DNSMapping
	anomaly    *AnomalyDetector

	// --- Контекст устройства ---
	localIPs   map[string]bool
	routerMode bool

	// --- Отображение ---
	profileSNI string
	groupBy    string // "app" | "device" | ""
	appFilter  string
	outputMode string // "text" | "json"
	showPTR    bool
	quiet      bool
	dnsAge     time.Duration

	// --- PCAP-режим (чтение из файла) ---
	pcapReader *pcapgo.Reader
	pcapFile   *os.File

	// --- Policy / baseline ---
	policy            *policy.Policy
	baselineRef       *baseline.Baseline
	violations        []policy.Violation
	violationSeen     map[string]bool // дедуп по (rule, actual)
	violationsEmitted map[string]bool // какие нарушения уже ушли в JSON
	violationsMu      sync.Mutex

	stats CaptureStats

	printCycle int // номер цикла вывода; инкрементируется в printAll
}

type CaptureStats struct {
	mu sync.Mutex

	PacketsReceived  uint64
	PacketsProcessed uint64
	PacketsTruncated uint64
	DecodeErrors     uint64
	NoIPLayer        uint64
	ShortPackets     uint64

	BytesReceived  uint64
	BytesProcessed uint64

	StartedAt time.Time
}

// statsSnapshot — копия статистики, безопасная для печати без мьютекса.
type statsSnapshot struct {
	PacketsReceived, PacketsProcessed, PacketsTruncated uint64
	DecodeErrors, NoIPLayer, ShortPackets               uint64
	BytesReceived, BytesProcessed                       uint64
	StartedAt                                           time.Time
}

func (c *Capture) statsSnapshot() statsSnapshot {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	return statsSnapshot{
		PacketsReceived:  c.stats.PacketsReceived,
		PacketsProcessed: c.stats.PacketsProcessed,
		PacketsTruncated: c.stats.PacketsTruncated,
		DecodeErrors:     c.stats.DecodeErrors,
		NoIPLayer:        c.stats.NoIPLayer,
		ShortPackets:     c.stats.ShortPackets,
		BytesReceived:    c.stats.BytesReceived,
		BytesProcessed:   c.stats.BytesProcessed,
		StartedAt:        c.stats.StartedAt,
	}
}

// localAddresses возвращает IP-адреса интерфейса и маппинг IP→MAC.
func localAddresses(iface string) (map[string]bool, map[string]string) {
	ips := make(map[string]bool)
	macs := make(map[string]string)

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return ips, macs // интерфейс без адресов — не ошибка
	}
	mac := ifi.HardwareAddr.String()

	addrs, err := ifi.Addrs()
	if err != nil {
		return ips, macs
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP.String()
		ips[ip] = true
		if mac != "" {
			macs[ip] = mac
		}
	}
	return ips, macs
}

func New(iface string, snaplen int, verbose bool) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, int32(snaplen), true, 0)
	if err != nil {
		return nil, fmt.Errorf("open interface %s: %w", iface, err)
	}

	localIPs, localMACs := localAddresses(iface)

	anomalyDetector := NewAnomalyDetector()
	dnsMapping := NewDNSMapping()

	flowTable := NewFlowTable()
	flowTable.anomaly = anomalyDetector
	flowTable.dnsMapping = dnsMapping
	hostname, _ := os.Hostname()
	flowTable.SetLocalHostname(hostname)
	flowTable.SetLocalMACs(localMACs)

	return &Capture{
		handle:     handle,
		verbose:    verbose,
		stopCh:     make(chan struct{}),
		flows:      flowTable,
		dnsTable:   NewDNSTable(),
		dnsMapping: dnsMapping,
		anomaly:    anomalyDetector,
		localIPs:   localIPs,
		iface:      iface,
		snaplen:    snaplen,
		outputMode: "text",
	}, nil
}

// --- Конфигурация (вызывать до Run) ---

func (c *Capture) SetMinPkts(n int)                 { c.flows.SetMinPkts(n) }
func (c *Capture) SetHideIdle(v bool)               { c.flows.SetHideIdle(v) }
func (c *Capture) SetQuiet(v bool)                  { c.quiet = v }
func (c *Capture) SetActiveOnly(n int)              { c.flows.SetActiveOnly(n) }
func (c *Capture) SetProfile(sni string)            { c.profileSNI = sni }
func (c *Capture) SetBaseline(b *baseline.Baseline) { c.baselineRef = b }
func (c *Capture) SetPolicy(p *policy.Policy)       { c.policy = p }

func (c *Capture) SetDNSAge(d time.Duration) {
	c.dnsAge = d
	c.dnsTable.SetMaxAge(d)
}

func (c *Capture) SetShowPTR(v bool) {
	c.showPTR = v
	c.dnsTable.SetShowPTR(v)
}

func (c *Capture) SetGroupBy(s string) {
	c.groupBy = s
	c.flows.SetGroupByDevice(s == "device")
}

func (c *Capture) SetAppFilter(s string) { c.appFilter = s; c.flows.SetAppFilter(s) }
func (c *Capture) SetRouterMode(v bool)  { c.routerMode = v }

func (c *Capture) SetFilter(expr string) error {
	c.filter = expr
	if c.pcapReader != nil {
		return fmt.Errorf("BPF-фильтр не поддерживается при чтении PCAP")
	}
	if err := c.handle.SetBPFFilter(expr); err != nil {
		return fmt.Errorf("set BPF filter %q: %w", expr, err)
	}
	return nil
}

func (c *Capture) SetOutputMode(mode string) {
	if mode != "json" {
		mode = "text"
	}
	c.outputMode = mode
}

// --- Жизненный цикл ---

// Close останавливает захват и освобождает ресурсы (handle, PCAP-файл).
// Идемпотентен; вызывать после завершения Run (defer — после <-done).
func (c *Capture) Close() {
	c.Stop()
	c.flows.Close()

	if c.pcapFile != nil {
		c.pcapFile.Close()
		c.pcapFile = nil
	}
	if c.handle != nil {
		c.handle.Close()
	}
}

// Run запускает захват; блокируется до Stop() или закрытия канала пакетов.
func (c *Capture) Run() {
	if c.pcapReader != nil {
		c.RunFromPCAP()
		return
	}

	packets := c.handle.Listen()

	c.stats.mu.Lock()
	c.stats.StartedAt = time.Now()
	c.stats.mu.Unlock()

	// Печать и enrich — в отдельных горутинах, основной цикл только читает пакеты.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.printLoop() }()
	go func() { defer wg.Done(); c.enrichLoop() }()
	defer wg.Wait()

	for {
		select {
		case <-c.stopCh:
			return
		case raw, ok := <-packets:
			if !ok {
				// Канал закрылся (захват умер) — завершаемся штатно:
				// финальный вывод будет напечатан, горутины не утекут.
				c.Stop()
				return
			}
			c.processData(raw.B)
		}
	}
}

func (c *Capture) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// --- Обработка пакетов ---

// packetInfo — результат разбора одного Ethernet-кадра.
type packetInfo struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	isIPv6           bool

	proto    string // "TCP" | "UDP" | "OTHER"
	payload  []byte
	tcpFlags TCPFlags
	seq      uint32
}

func (p *packetInfo) flowKey() FlowKey {
	return FlowKey{
		LocalIP: p.srcIP, LocalPort: p.srcPort,
		RemoteIP: p.dstIP, RemotePort: p.dstPort,
		Proto: p.proto,
	}
}

func (p *packetInfo) reverseFlowKey() FlowKey {
	return FlowKey{
		LocalIP: p.dstIP, LocalPort: p.dstPort,
		RemoteIP: p.srcIP, RemotePort: p.srcPort,
		Proto: p.proto,
	}
}

// isDNSPort: UDP/53, UDP/5353, TCP/53.
func (p *packetInfo) isDNSPort() bool {
	switch p.proto {
	case protoUDP:
		return p.srcPort == portDNS || p.dstPort == portDNS ||
			p.srcPort == portMDNS || p.dstPort == portMDNS
	case protoTCP:
		return p.srcPort == portDNS || p.dstPort == portDNS
	}
	return false
}

func (p *packetInfo) isDNSQuery() bool {
	switch p.proto {
	case protoTCP:
		return p.dstPort == portDNS
	default:
		return p.dstPort == portDNS || p.dstPort == portMDNS
	}
}

func (p *packetInfo) isDNSResponse() bool {
	switch p.proto {
	case protoTCP:
		return p.srcPort == portDNS
	default:
		return p.srcPort == portDNS || p.srcPort == portMDNS
	}
}

func (c *Capture) processData(data []byte) {
	if len(data) < ethHeaderLen {
		c.noteShortPacket(data)
		return
	}

	c.stats.mu.Lock()
	c.stats.PacketsReceived++
	c.stats.BytesReceived += uint64(len(data))
	c.stats.mu.Unlock()

	p, ok := c.decode(data)
	if !ok {
		return
	}

	c.stats.mu.Lock()
	c.stats.PacketsProcessed++
	c.stats.BytesProcessed += uint64(len(data))
	c.stats.mu.Unlock()

	isOutbound := c.directionOf(p.srcIP, p.dstIP)
	c.flows.Update(p.srcIP, p.srcPort, p.dstIP, p.dstPort, p.proto, len(data), isOutbound, p.tcpFlags, p.seq)

	c.checkPolicyIPv6(p)
	c.handleTLSSNI(p)
	c.handleDNS(p)
	c.handleQUICSNI(p)
	c.handleVPN(p, isOutbound)
}

// noteShortPacket учитывает (и в verbose показывает) кадры короче Ethernet-заголовка.
func (c *Capture) noteShortPacket(data []byte) {
	c.stats.mu.Lock()
	c.stats.ShortPackets++
	c.stats.PacketsReceived++
	c.stats.BytesReceived += uint64(len(data))
	n := c.stats.ShortPackets
	c.stats.mu.Unlock()

	if c.verbose && n <= shortDebugLimit {
		fmt.Fprintf(os.Stderr, "[SHORT] len=%d data=%x\n", len(data), data)
	}
}

// decode парсит Ethernet-кадр; false — пакет пропускается (статистика учтена).
func (c *Capture) decode(data []byte) (*packetInfo, bool) {
	gp := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)

	if gp.ErrorLayer() != nil {
		c.stats.mu.Lock()
		c.stats.DecodeErrors++
		c.stats.mu.Unlock()
		return nil, false
	}

	// gopacket.NewPacket не заполняет Metadata, так что прежняя проверка
	// CaptureLength < Length никогда не срабатывала. Усечение ловим
	// эвристикой: кадр ровно в snaplen байт мог быть обрезан.
	if c.snaplen > 0 && len(data) >= c.snaplen {
		c.stats.mu.Lock()
		c.stats.PacketsTruncated++
		c.stats.mu.Unlock()
	}

	ipLayer := gp.NetworkLayer()
	if ipLayer == nil {
		c.stats.mu.Lock()
		c.stats.NoIPLayer++
		c.stats.mu.Unlock()
		return nil, false
	}

	p := &packetInfo{proto: "OTHER"}
	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		p.srcIP, p.dstIP = ip.SrcIP.String(), ip.DstIP.String()
	case *layers.IPv6:
		p.srcIP, p.dstIP = ip.SrcIP.String(), ip.DstIP.String()
		p.isIPv6 = true
	}

	if tcp, ok := gp.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		p.proto, p.srcPort, p.dstPort = protoTCP, uint16(tcp.SrcPort), uint16(tcp.DstPort)
		p.payload, p.seq = tcp.Payload, tcp.Seq
		p.tcpFlags = tcpFlagsOf(tcp)
	} else if udp, ok := gp.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		p.proto, p.srcPort, p.dstPort = protoUDP, uint16(udp.SrcPort), uint16(udp.DstPort)
		p.payload = udp.Payload
	}

	return p, true
}

// directionOf решает, исходит ли пакет от "нас" (outbound).
func (c *Capture) directionOf(srcIP, dstIP string) bool {
	if !c.routerMode {
		return c.localIPs[srcIP]
	}
	srcLAN, dstLAN := isLANIP(srcIP), isLANIP(dstIP)
	switch {
	case srcLAN && !dstLAN:
		return true // LAN → Internet
	case !srcLAN && dstLAN:
		return false // Internet → LAN
	case srcLAN && dstLAN:
		return !c.localIPs[srcIP] // внутри LAN: чужое устройство → не наш трафик
	default:
		return false
	}
}

// --- Прикладные обработчики ---

// checkPolicyIPv6: IPv6 запрещён политикой.
func (c *Capture) checkPolicyIPv6(p *packetInfo) {
	if c.policy == nil || c.policy.IsIPv6Allowed() || !p.isIPv6 {
		return
	}
	c.addViolation(policy.Violation{
		Rule:     "ipv6",
		Expected: "disabled",
		Actual:   fmt.Sprintf("%s → %s", p.srcIP, p.dstIP),
		Detail:   "IPv6-трафик при policy.ipv6=false",
	})
}

// handleTLSSNI аккумулирует payload ClientHello (фрагментация допустима)
// и извлекает SNI; затем помечает соединение в детекторе аномалий.
func (c *Capture) handleTLSSNI(p *packetInfo) {
	if p.proto != protoTCP || p.dstPort != portHTTPS || len(p.payload) == 0 {
		return
	}
	sni := c.flows.AppendPayload(p.flowKey(), p.payload)
	if sni != "" && c.anomaly != nil {
		c.anomaly.MarkConnected(sni)
	}
}

// handleDNS обрабатывает DNS/mDNS: таблицу ответов, аномалии запросов
// и policy-проверку резолвера.
// Внимание: для mDNS (оба порта 5353) запрос и ответ — не взаимоисключающие
// ветки, поэтому отдельные if, а не switch.
func (c *Capture) handleDNS(p *packetInfo) {
	if len(p.payload) == 0 || !p.isDNSPort() {
		return
	}

	c.dnsTable.Update(p.payload, p.srcIP, p.dstIP, p.srcPort, p.dstPort, p.proto)

	if p.isDNSQuery() {
		c.handleDNSQuery(p)
	}
	if p.isDNSResponse() {
		c.dnsMapping.Update(p.payload, p.dstIP, p.srcIP, p.proto)
	}
}

func (c *Capture) handleDNSQuery(p *packetInfo) {
	msg := dnsMessage(p.payload, p.proto)
	if msg == nil {
		return
	}
	name, qtype, ok := parseDNSQuery(msg)
	if !ok {
		return
	}

	if c.anomaly != nil {
		if leak := c.anomaly.CheckDNSLeak(p.dstIP, name); leak != "" {
			c.dnsTable.SetFlags(name, qtype, p.srcIP, p.dstIP, leak)
		}
		if flag := c.anomaly.CheckDomain(name, true); flag != "" {
			c.dnsTable.SetFlags(name, qtype, p.srcIP, p.dstIP, flag)
		}
		c.anomaly.RecordDNSOnly(name)
	}

	// Policy: разрешён ли резолвер. Не зависит от anomaly.
	if c.policy != nil && !c.policy.IsResolverAllowed(p.dstIP) {
		c.dnsTable.SetFlags(name, qtype, p.srcIP, p.dstIP,
			fmt.Sprintf("⚠POLICY-DNS→%s", p.dstIP))
	}
}

// handleQUICSNI извлекает SNI из QUIC Initial (UDP/443).
func (c *Capture) handleQUICSNI(p *packetInfo) {
	if p.proto != protoUDP || len(p.payload) == 0 ||
		(p.srcPort != portHTTPS && p.dstPort != portHTTPS) {
		return
	}
	sni := extractQUICSNI(p.payload, p.srcIP, p.dstIP, p.srcPort, p.dstPort)
	if sni == "" {
		return
	}

	// Локальная сторона — та, у которой не 443.
	key := p.flowKey()
	if p.srcPort == portHTTPS {
		key = p.reverseFlowKey()
	}
	c.flows.SetSNI(key, sni)
	if c.anomaly != nil {
		c.anomaly.MarkConnected(sni)
	}
}

// handleVPN детектит VPN-протоколы в payload исходящих пакетов.
func (c *Capture) handleVPN(p *packetInfo, isOutbound bool) {
	if !isOutbound || len(p.payload) == 0 || (p.proto != protoTCP && p.proto != protoUDP) {
		return
	}
	if det := detectVPN(p.payload, p.proto, p.srcPort, p.dstPort); det != nil {
		c.flows.MarkVPN(p.srcIP, p.srcPort, p.dstIP, p.dstPort, p.proto, det)
	}
}

// --- Фоновые горутины ---

func (c *Capture) printLoop() {
	ticker := time.NewTicker(printInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			c.printAll() // финальный вывод
			return
		case <-ticker.C:
			c.printAll()
		}
	}
}

func (c *Capture) enrichLoop() {
	ticker := time.NewTicker(enrichInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			c.flows.Enrich()
			return
		case <-ticker.C:
			c.flows.Enrich()
		}
	}
}

// --- Вывод ---

func (c *Capture) printAll() {
	if c.quiet {
		return
	}
	c.printCycle++ // цикл инкрементируется ДО baseline-диффа: весь вывод одного прохода — один cycle
	if c.baselineRef != nil {
		c.printBaselineDiffJSON(c.baselineRef)
	}
	if c.outputMode == "json" {
		c.printAllJSON()
		return
	}
	c.printText()
}

func (c *Capture) printText() {
	c.flows.Enrich()

	if c.groupBy == "app" || c.groupBy == "device" {
		c.flows.PrintApps()
	} else {
		c.flows.Print()
	}
	c.dnsTable.Print()

	flows := c.flows.Snapshot()
	printAttribution(flows, c.dnsMapping)
	printProxySuspicions(flows, c.dnsMapping, c.anomaly)
	printProxyProcesses(flows)

	c.printAnomalies()
	c.flows.PrintProfile(c.profileSNI)
	c.checkDirectOutbound()
	c.printPolicyViolations()

	// LAN inventory (только в router-mode)
	if c.routerMode {
		c.flows.PrintDevices()
	}

	c.printHealth()

	if c.anomaly != nil {
		c.anomaly.SaveHistory()
	}
}

func (c *Capture) printHealth() {
	s := c.statsSnapshot()

	uptime := time.Since(s.StartedAt).Truncate(time.Second)

	quality := "✓ complete"
	if s.PacketsTruncated > 0 || s.DecodeErrors > 0 {
		quality = "⚠ incomplete"
	}

	fmt.Printf("\n=== Capture Health ===\n")
	fmt.Printf("Interface:      %s\n", c.iface)
	fmt.Printf("Filter:         %s\n", c.filter)
	fmt.Printf("Snaplen:        %d\n", c.snaplen)
	fmt.Printf("Uptime:         %s\n\n", uptime)
	fmt.Printf("Packets:\n")
	fmt.Printf("  received:     %d\n", s.PacketsReceived)
	fmt.Printf("  processed:    %d\n", s.PacketsProcessed)
	fmt.Printf("  truncated:    %d\n", s.PacketsTruncated)
	fmt.Printf("  decode err:   %d\n", s.DecodeErrors)
	fmt.Printf("  no IP layer:  %d\n", s.NoIPLayer)
	fmt.Printf("  short pkts:   %d\n\n", s.ShortPackets)
	fmt.Printf("Bytes:\n")
	fmt.Printf("  received:     %s\n", humanBytes(s.BytesReceived))
	fmt.Printf("  processed:    %s\n\n", humanBytes(s.BytesProcessed))
	fmt.Printf("Quality:        %s\n", quality)

	if quality == "⚠ incomplete" {
		fmt.Printf("⚠  Вывод может быть неполным — часть пакетов потеряна или усечена.\n")
	}
}

// printAnomalies выводит сводку подозрительных доменов, обогащённую процессами.
func (c *Capture) printAnomalies() {
	if c.anomaly == nil {
		return
	}

	records := c.anomaly.CollectAnomalies(anomalyWindow)
	if len(records) == 0 {
		return
	}

	flows := c.flows.Snapshot()

	// Процесс для домена: сначала по SNI, затем по IP из DNS-маппинга.
	findProcess := func(domain string) string {
		for _, f := range flows {
			if f.SNI == domain && f.Comm != "" {
				return fmt.Sprintf("%s(%d)", f.Comm, f.PID)
			}
		}
		if c.dnsMapping == nil {
			return ""
		}
		for _, ip := range c.dnsMapping.IPsForName(domain) {
			for _, f := range flows {
				if f.Key.RemoteIP == ip && f.Comm != "" {
					return fmt.Sprintf("%s(%d)", f.Comm, f.PID)
				}
			}
		}
		return ""
	}

	for i := range records {
		if records[i].Process != "" {
			continue
		}
		if proc := findProcess(records[i].Domain); proc != "" {
			records[i].Process = proc
			c.anomaly.SetProcessForDomain(records[i].Domain, proc)
		}
	}

	c.anomaly.PrintAnomalies(anomalyWindow)
}

// --- Policy ---

func (c *Capture) addViolation(v policy.Violation) {
	c.violationsMu.Lock()
	defer c.violationsMu.Unlock()

	if c.violationSeen == nil {
		c.violationSeen = make(map[string]bool)
	}
	key := v.Rule + "\x00" + v.Actual
	if c.violationSeen[key] {
		return
	}
	c.violationSeen[key] = true
	c.violations = append(c.violations, v)
}

// checkDirectOutbound: домены из allow_direct должны идти напрямую,
// а не через прокси.
func (c *Capture) checkDirectOutbound() {
	if c.policy == nil || len(c.policy.AllowDirect) == 0 {
		return
	}
	for _, f := range c.flows.Snapshot() {
		if f.SNI == "" || f.Class == ClassDirect || f.Class == ClassUnknown {
			continue
		}
		if !slices.Contains(c.policy.AllowDirect, f.SNI) {
			continue
		}
		c.addViolation(policy.Violation{
			Rule:     "direct_outbound",
			Expected: "direct",
			Actual:   f.SNI,
			Detail:   fmt.Sprintf("class=proxy, remote=%s", f.Key.RemoteIP),
		})
	}
}

func (c *Capture) printPolicyViolations() {
	c.violationsMu.Lock()
	vs := make([]policy.Violation, len(c.violations))
	copy(vs, c.violations)
	c.violationsMu.Unlock()

	if len(vs) == 0 {
		return
	}

	fmt.Printf("\n=== ⚠ Policy Violations (%d) ===\n", len(vs))
	fmt.Printf("%-20s %-20s %-30s %s\n", "RULE", "EXPECTED", "ACTUAL", "DETAIL")
	for _, v := range vs {
		fmt.Printf("%-20s %-20s %-30s %s\n",
			truncate(v.Rule, 20),
			truncate(v.Expected, 20),
			truncate(v.Actual, 30),
			v.Detail)
	}
	fmt.Println()
}

// --- TCP options ---

func tcpFlagsOf(tcp *layers.TCP) TCPFlags {
	tf := TCPFlags{
		SYN: tcp.SYN, ACK: tcp.ACK, FIN: tcp.FIN, RST: tcp.RST, PSH: tcp.PSH,
		Payload: tcp.Payload,
	}
	if tcp.SYN && !tcp.ACK { // открытие соединения — опции имеют смысл только тут
		tf.MSS = extractMSS(tcp.Options)
		tf.WindowScale = extractWindowScale(tcp.Options)
		tf.HasTimestamps = hasOption(tcp.Options, layers.TCPOptionKindTimestamps)
		tf.HasSACK = hasOption(tcp.Options, layers.TCPOptionKindSACKPermitted)
	}
	return tf
}

func extractMSS(opts []layers.TCPOption) uint16 {
	for _, o := range opts {
		if o.OptionType == layers.TCPOptionKindMSS && len(o.OptionData) >= 2 {
			return uint16(o.OptionData[0])<<8 | uint16(o.OptionData[1])
		}
	}
	return 0
}

func extractWindowScale(opts []layers.TCPOption) uint8 {
	for _, o := range opts {
		if o.OptionType == layers.TCPOptionKindWindowScale && len(o.OptionData) >= 1 {
			return o.OptionData[0]
		}
	}
	return 0
}

func hasOption(opts []layers.TCPOption, kind layers.TCPOptionKind) bool {
	for _, o := range opts {
		if o.OptionType == kind {
			return true
		}
	}
	return false
}

// --- Утилиты ---

// isLANIP определяет, является ли IP локальным (RFC1918 или link-local).
func isLANIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsPrivate() {
		return true
	}
	// Multicast (224.0.0.0/4, ff00::/8) — локальный
	if parsed.IsMulticast() {
		return true
	}
	// IPv6 ULA (fc00::/7)
	if len(parsed) == net.IPv6len && (parsed[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

// BuildBaseline собирает снимок текущего состояния.
func (c *Capture) BuildBaseline() *baseline.Baseline {
	flows := c.flows.Snapshot()

	domainsSet := make(map[string]bool)
	procsSet := make(map[string]bool)
	devicesSet := make(map[string]bool)
	ja3 := make(map[string]string)
	ja4 := make(map[string]string)

	for _, f := range flows {
		if f.SNI != "" {
			domainsSet[f.SNI] = true
		} else if f.Hostname != "" {
			domainsSet[f.Hostname] = true
		}
		if f.Comm != "" {
			procsSet[f.Comm] = true
		}
		if f.Key.LocalIP != "" {
			devicesSet[f.Key.LocalIP] = true
		}

		// JA3/JA4 — по процессу. Пропускаем proxy/vpn:
		// у них JA3/JA4 меняется каждый сеанс.
		if f.Comm != "" && f.Class != ClassProxy && f.Class != ClassVPN {
			if f.JA3 != "" {
				ja3[f.Comm] = f.JA3
			}
			if f.JA4 != "" {
				ja4[f.Comm] = f.JA4
			}
		}
	}

	return &baseline.Baseline{
		Schema:    baseline.SchemaVersion,
		Created:   time.Now().UTC(),
		Iface:     c.iface,
		Domains:   sortedKeys(domainsSet),
		Processes: sortedKeys(procsSet),
		Devices:   sortedKeys(devicesSet),
		JA3:       ja3,
		JA4:       ja4,
	}
}

// sortedKeys возвращает отсортированные ключи map.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
