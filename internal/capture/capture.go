package capture

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/huatuo-ai/go-pcap"
)

type Capture struct {
	handle     *pcap.Handle
	verbose    bool
	stopCh     chan struct{}
	stopOnce   sync.Once
	flows      *FlowTable
	dnsTable   *DNSTable
	dnsMapping *DNSMapping
	anomaly    *AnomalyDetector
	localIPs   map[string]bool
	profileSNI string
	routerMode bool
	groupBy    string // "app" | "device" | ""
	appFilter  string // фильтр по имени приложения
	iface      string
	filter     string
	snaplen    int
	stats      CaptureStats
	outputMode string // "text" | "json"
	printCycle int
	showPTR    bool
}

type CaptureStats struct {
	mu sync.Mutex

	PacketsReceived  uint64
	PacketsProcessed uint64
	PacketsTruncated uint64
	DecodeErrors     uint64
	NoIPLayer        uint64

	BytesReceived  uint64
	BytesProcessed uint64

	StartedAt time.Time
}

func New(iface string, snaplen int, verbose bool) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, int32(snaplen), true, 0)
	if err != nil {
		return nil, err
	}

	localIPs := make(map[string]bool)
	if ifi, err := net.InterfaceByName(iface); err == nil {
		if addrs, err := ifi.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					localIPs[ipn.IP.String()] = true
				}
			}
		}
	}

	anomalyDetector := NewAnomalyDetector()
	flowTable := NewFlowTable()
	flowTable.anomaly = anomalyDetector

	return &Capture{
		handle:     handle,
		verbose:    verbose,
		stopCh:     make(chan struct{}),
		flows:      flowTable,
		dnsTable:   NewDNSTable(),
		dnsMapping: NewDNSMapping(),
		anomaly:    anomalyDetector,
		localIPs:   localIPs,
		iface:      iface,
		snaplen:    snaplen,
		outputMode: "text",
	}, nil
}

func (c *Capture) SetMinPkts(n int)          { c.flows.SetMinPkts(n) }
func (c *Capture) SetHideIdle(v bool)        { c.flows.SetHideIdle(v) }
func (c *Capture) SetActiveOnly(n int)       { c.flows.SetActiveOnly(n) }
func (c *Capture) SetProfile(sni string)     { c.profileSNI = sni }
func (c *Capture) SetDNSAge(d time.Duration) { c.dnsTable.SetMaxAge(d) }
func (c *Capture) SetShowPTR(v bool) {
	c.showPTR = v
	c.dnsTable.SetShowPTR(v)
}
func (c *Capture) SetGroupBy(s string)   { c.groupBy = s }
func (c *Capture) SetAppFilter(s string) { c.appFilter = s; c.flows.SetAppFilter(s) }
func (c *Capture) SetRouterMode(v bool)  { c.routerMode = v }

func (c *Capture) SetFilter(expr string) error {
	c.filter = expr
	return c.handle.SetBPFFilter(expr)
}

func (c *Capture) SetOutputMode(mode string) {
	if mode != "json" {
		mode = "text"
	}
	c.outputMode = mode
}

func (c *Capture) Run() {
	packets := c.handle.Listen()

	c.stats.StartedAt = time.Now()

	// Горутина печати — отдельно от чтения пакетов
	printDone := make(chan struct{})
	go func() {
		defer close(printDone)
		c.printLoop()
	}()

	// Горутина enrich — отдельно
	enrichDone := make(chan struct{})
	go func() {
		defer close(enrichDone)
		c.enrichLoop()
	}()

	// Основной цикл: только чтение пакетов
	for {
		select {
		case <-c.stopCh:
			// Ждём завершения printLoop и enrichLoop
			<-printDone
			<-enrichDone
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			c.process(pkt)
		}
	}
}

func (c *Capture) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

func (c *Capture) Close() {
	c.Stop()
	c.handle.Close()
}

func (c *Capture) process(pkt pcap.Packet) {
	data := pkt.B

	c.stats.mu.Lock()
	c.stats.PacketsReceived++
	c.stats.BytesReceived += uint64(len(data))
	c.stats.mu.Unlock()

	packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)

	// Проверяем ошибки декодирования
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		c.stats.mu.Lock()
		c.stats.DecodeErrors++
		c.stats.mu.Unlock()
		return
	}

	// Проверяем усечение пакета (snaplen)
	if meta := packet.Metadata(); meta != nil {
		if meta.CaptureLength > 0 && meta.Length > 0 && meta.CaptureLength < meta.Length {
			c.stats.mu.Lock()
			c.stats.PacketsTruncated++
			c.stats.mu.Unlock()
		}
	}

	ipLayer := packet.NetworkLayer()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ipLayer == nil {
		c.stats.mu.Lock()
		c.stats.NoIPLayer++
		c.stats.mu.Unlock()
		return
	}

	c.stats.mu.Lock()
	c.stats.PacketsProcessed++
	c.stats.BytesProcessed += uint64(len(data))
	c.stats.mu.Unlock()

	var srcIP, dstIP string
	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	case *layers.IPv6:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	proto := "OTHER"
	var srcPort, dstPort uint16
	var tf TCPFlags
	var payload []byte
	var seq uint32

	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		proto = "TCP"
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		payload = tcp.Payload
		seq = tcp.Seq

		tf = TCPFlags{
			SYN: tcp.SYN, ACK: tcp.ACK, FIN: tcp.FIN, RST: tcp.RST, PSH: tcp.PSH,
			Payload: tcp.Payload,
		}

		if tcp.SYN && !tcp.ACK {
			tf.MSS = extractMSS(tcp.Options)
			tf.WindowScale = extractWindowScale(tcp.Options)
			tf.HasTimestamps = hasOption(tcp.Options, 8)
			tf.HasSACK = hasOption(tcp.Options, 4)
		}
	} else if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		proto = "UDP"
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		payload = udp.Payload
	}

	var isOutbound bool
	if c.routerMode {
		srcIsLAN := isLANIP(srcIP)
		dstIsLAN := isLANIP(dstIP)

		switch {
		case srcIsLAN && !dstIsLAN:
			isOutbound = true
		case !srcIsLAN && dstIsLAN:
			isOutbound = false
		case srcIsLAN && dstIsLAN:
			isOutbound = !c.localIPs[srcIP]
		default:
			isOutbound = false
		}
	} else {
		isOutbound = c.localIPs[srcIP]
	}

	c.flows.Update(srcIP, srcPort, dstIP, dstPort, proto, len(data), isOutbound, tf, seq)

	// SNI: аккумулируем payload и пытаемся извлечь (работает с фрагментацией)
	if isOutbound && proto == "TCP" && dstPort == 443 && len(payload) > 0 {
		key := FlowKey{
			LocalIP:    srcIP,
			LocalPort:  srcPort,
			RemoteIP:   dstIP,
			RemotePort: dstPort,
			Proto:      proto,
		}
		if sni := c.flows.AppendPayload(key, payload); sni != "" && c.anomaly != nil {
			c.anomaly.MarkConnected(sni)
		}
	}

	// DNS-парсер (UDP/53, UDP/5353, TCP/53)
	if len(payload) > 0 {
		if (proto == "UDP" && (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353)) ||
			(proto == "TCP" && (srcPort == 53 || dstPort == 53)) {
			c.dnsTable.Update(payload, srcIP, dstIP, srcPort, dstPort, proto)

			// Если это запрос (dstPort == 53) — проверяем аномалии
			if dstPort == 53 && c.anomaly != nil {
				if name, qtype, ok := parseDNSQuery(payload); ok {
					if leak := c.anomaly.CheckDNSLeak(dstIP, name); leak != "" {
						c.dnsTable.SetFlags(name, qtype, srcIP, dstIP, leak)
					}
					if flag := c.anomaly.CheckDomain(name, true); flag != "" {
						c.dnsTable.SetFlags(name, qtype, srcIP, dstIP, flag)
					}
					if c.anomaly != nil {
						c.anomaly.RecordDNSOnly(name)
					}
				}
			}

			// Если это ответ — строим маппинг name → IP
			if srcPort == 53 || srcPort == 5353 {
				c.dnsMapping.Update(payload)
			}
		}
	}

	// QUIC-парсер: только UDP/443, только Initial
	if proto == "UDP" && len(payload) > 0 && (srcPort == 443 || dstPort == 443) {
		if sni := extractQUICSNI(payload, srcIP, dstIP, srcPort, dstPort); sni != "" {
			key := FlowKey{
				LocalIP:    srcIP,
				LocalPort:  srcPort,
				RemoteIP:   dstIP,
				RemotePort: dstPort,
				Proto:      proto,
			}
			// Определяем локальную сторону для нормализации
			if srcPort == 443 {
				key = FlowKey{
					LocalIP:    dstIP,
					LocalPort:  dstPort,
					RemoteIP:   srcIP,
					RemotePort: srcPort,
					Proto:      proto,
				}
			}
			c.flows.SetSNI(key, sni)
			if c.anomaly != nil {
				c.anomaly.MarkConnected(sni)
			}
		}
	}

	// VPN-детект: только для исходящих пакетов, только первый пакет потока
	if isOutbound && len(payload) > 0 && (proto == "UDP" || proto == "TCP") {
		if det := detectVPN(payload, srcIP, dstIP, srcPort, dstPort); det != nil {
			c.flows.MarkVPN(srcIP, srcPort, dstIP, dstPort, proto, det)
		}
	}
}

func (c *Capture) printLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			c.printAll()
			return
		case <-ticker.C:
			c.printAll()
		}
	}
}

func (c *Capture) enrichLoop() {
	ticker := time.NewTicker(1 * time.Second)
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

func (c *Capture) printAll() {
	if c.outputMode == "json" {
		c.printAllJSON()
		return
	}

	// текстовый режим — как раньше
	c.flows.Enrich()
	if c.groupBy == "app" || c.groupBy == "device" {
		c.flows.PrintApps()
	} else {
		c.flows.Print()
	}
	c.dnsTable.Print()
	printAttribution(c.flows.Snapshot(), c.dnsMapping)
	printProxySuspicions(c.flows.Snapshot(), c.dnsMapping, c.anomaly)
	printProxyProcesses(c.flows.Snapshot())
	c.printAnomalies()
	c.flows.PrintProfile(c.profileSNI)
	c.printHealth()

	if c.anomaly != nil {
		c.anomaly.SaveHistory()
	}
}

func (c *Capture) printHealth() {
	c.stats.mu.Lock()
	s := c.stats
	c.stats.mu.Unlock()

	uptime := time.Since(s.StartedAt).Truncate(time.Second)

	quality := "✓ complete"
	if s.PacketsTruncated > 0 || s.DecodeErrors > 0 {
		quality = "⚠ incomplete"
	}

	fmt.Printf("\n=== Capture Health ===\n")
	fmt.Printf("Interface:      %s\n", c.iface)
	fmt.Printf("Filter:         %s\n", c.filter)
	fmt.Printf("Snaplen:        %d\n", c.snaplen)
	fmt.Printf("Uptime:         %s\n", uptime)
	fmt.Printf("\n")
	fmt.Printf("Packets:\n")
	fmt.Printf("  received:     %d\n", s.PacketsReceived)
	fmt.Printf("  processed:    %d\n", s.PacketsProcessed)
	fmt.Printf("  truncated:    %d\n", s.PacketsTruncated)
	fmt.Printf("  decode err:   %d\n", s.DecodeErrors)
	fmt.Printf("  no IP layer:  %d\n", s.NoIPLayer)
	fmt.Printf("\n")
	fmt.Printf("Bytes:\n")
	fmt.Printf("  received:     %s\n", humanBytes(s.BytesReceived))
	fmt.Printf("  processed:    %s\n", humanBytes(s.BytesProcessed))
	fmt.Printf("\n")
	fmt.Printf("Quality:        %s\n", quality)

	if quality == "⚠ incomplete" {
		fmt.Printf("⚠  Вывод может быть неполным — часть пакетов потеряна или усечена.\n")
	}
}

func extractMSS(opts []layers.TCPOption) uint16 {
	for _, o := range opts {
		if o.OptionType == 2 && len(o.OptionData) >= 2 {
			return uint16(o.OptionData[0])<<8 | uint16(o.OptionData[1])
		}
	}
	return 0
}

func extractWindowScale(opts []layers.TCPOption) uint8 {
	for _, o := range opts {
		if o.OptionType == 3 && len(o.OptionData) >= 1 {
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

// printAnomalies выводит сводку подозрительных доменов с процессами.
func (c *Capture) printAnomalies() {
	if c.anomaly == nil {
		return
	}

	records := c.anomaly.CollectAnomalies(5 * time.Minute)
	if len(records) == 0 {
		return
	}

	// Обогащаем процессы
	flows := c.flows.Snapshot()

	for i := range records {
		if records[i].Process != "" {
			continue
		}

		// 1. Ищем процесс по SNI (прямое совпадение)
		for _, f := range flows {
			if f.SNI == records[i].Domain && f.Comm != "" {
				records[i].Process = fmt.Sprintf("%s(%d)", f.Comm, f.PID)
				break
			}
		}

		// 2. Если не нашли — ищем по IP, в который резолвился домен
		if records[i].Process == "" && c.dnsMapping != nil {
			ips := c.dnsMapping.IPsForName(records[i].Domain)
			for _, ip := range ips {
				for _, f := range flows {
					if f.Key.RemoteIP == ip && f.Comm != "" {
						records[i].Process = fmt.Sprintf("%s(%d)", f.Comm, f.PID)
						break
					}
				}
				if records[i].Process != "" {
					break
				}
			}
		}

		// 3. Обновляем запись в детекторе
		if records[i].Process != "" {
			c.anomaly.SetProcessForDomain(records[i].Domain, records[i].Process)
		}
	}

	c.anomaly.PrintAnomalies(5 * time.Minute)
}

// isLANIP определяет, является ли IP локальным (RFC1918 или link-local).
func isLANIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return true
	}
	if parsed.IsPrivate() {
		return true
	}
	// IPv6 ULA (fc00::/7)
	if len(parsed) == net.IPv6len && (parsed[0]&0xfe) == 0xfc {
		return true
	}
	return false
}
