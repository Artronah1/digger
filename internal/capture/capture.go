package capture

import (
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
	localIPs   map[string]bool
	profileSNI string
	routerMode bool
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

	return &Capture{
		handle:     handle,
		verbose:    verbose,
		stopCh:     make(chan struct{}),
		flows:      NewFlowTable(),
		dnsTable:   NewDNSTable(),
		dnsMapping: NewDNSMapping(),
		localIPs:   localIPs,
	}, nil
}

func (c *Capture) SetMinPkts(n int)      { c.flows.SetMinPkts(n) }
func (c *Capture) SetHideIdle(v bool)    { c.flows.SetHideIdle(v) }
func (c *Capture) SetActiveOnly(n int)   { c.flows.SetActiveOnly(n) }
func (c *Capture) SetProfile(sni string) { c.profileSNI = sni }
func (c *Capture) SetDNSAge(d time.Duration) { c.dnsTable.SetMaxAge(d) }
func (c *Capture) SetFilter(expr string) error { return c.handle.SetBPFFilter(expr) }
func (c *Capture) SetRouterMode(v bool) { c.routerMode = v }

func (c *Capture) Run() {
	packets := c.handle.Listen()

	printTicker := time.NewTicker(5 * time.Second)
	defer printTicker.Stop()

	enrichTicker := time.NewTicker(1 * time.Second)
	defer enrichTicker.Stop()

	for {
		select {
			case <-c.stopCh:
				c.flows.Enrich()
				c.flows.Print()
				c.dnsTable.Print()
				printAttribution(c.flows.Snapshot(), c.dnsMapping)
				c.flows.PrintProfile(c.profileSNI)
				return
			case <-enrichTicker.C:
				c.flows.Enrich()
			case <-printTicker.C:
				c.flows.Print()
				c.dnsTable.Print()
				printAttribution(c.flows.Snapshot(), c.dnsMapping)
				c.flows.PrintProfile(c.profileSNI)
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

	packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)

	ipLayer := packet.NetworkLayer()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ipLayer == nil {
		return
	}

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
				// LAN-клиент → внешний мир = outbound
				isOutbound = true
			case !srcIsLAN && dstIsLAN:
				// Внешний мир → LAN-клиент = inbound
				isOutbound = false
			case srcIsLAN && dstIsLAN:
				// LAN ↔ LAN. Если src — не адрес роутера, это клиент → outbound
				isOutbound = !c.localIPs[srcIP]
			default:
				// Ни то, ни другое (не должно случаться на br-lan)
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
		c.flows.AppendPayload(key, payload)
	}

	// DNS-парсер (UDP/53, UDP/5353, TCP/53)
	if len(payload) > 0 {
		if (proto == "UDP" && (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353)) ||
			(proto == "TCP" && (srcPort == 53 || dstPort == 53)) {
				c.dnsTable.Update(payload, srcIP, dstIP, srcPort, dstPort, proto)

				// Если это ответ — строим маппинг name → IP
				// Ответ идёт с srcPort == 53 (от сервера к клиенту)
				if srcPort == 53 || srcPort == 5353 {
					c.dnsMapping.Update(payload)
				}
			}
	}

	// QUIC-парсер: только UDP/443, только Initial
	if proto == "UDP" && len(payload) > 0 && (srcPort == 443 || dstPort == 443) {
		if sni := extractQUICSNI(payload, srcPort); sni != "" {
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
		}
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
