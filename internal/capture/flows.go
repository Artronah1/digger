package capture

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"digger/internal/dns"
	"digger/internal/netmap"
	"digger/internal/proc"
)

// --- Константы ---

const (
	// Хранение потоков.
	flowMaxAge     = time.Hour // простой дольше — поток вычищается
	flowSweepEvery = time.Minute
	maxTrackedSeqs = 4096 // предел карты seq на поток (память важнее точности)
	maxClientHello = 8192 // ClientHello больше не бывает — предел аккумулятора
	timelineSlots  = 60   // слотов таймлайна (по секунде)

	// Фильтры шума в Print.
	idleHideAfter  = 30 * time.Second
	noiseMaxRate   = 1.0   // пакетов/сек
	noiseMaxAvg    = 100.0 // байт
	noiseIdleAfter = 10 * time.Second
	noiseMaxBytes  = 10 * 1024

	maxBarLen = 50 // ширина гистограммы
)

// --- Классификация ---

// Classification — итоговая классификация потока.
type Classification int

const (
	ClassUnknown Classification = iota
	ClassDirect
	ClassProxy
	ClassVPN
)

func (c Classification) String() string {
	switch c {
	case ClassDirect:
		return "direct"
	case ClassProxy:
		return "proxy"
	case ClassVPN:
		return "vpn"
	default:
		return "unknown"
	}
}

// classPriority — приоритет классификации для агрегата (VPN > Proxy > Direct).
func classPriority(c Classification) int {
	switch c {
	case ClassVPN:
		return 4
	case ClassProxy:
		return 3
	case ClassDirect:
		return 2
	case ClassUnknown:
		return 1
	default:
		return 0
	}
}

// --- Реконструкция ClientHello ---

type ReconstructionStatus int

const (
	ReconUnknown ReconstructionStatus = iota
	ReconEmpty
	ReconPartial
	ReconComplete
	ReconGap
)

func (r ReconstructionStatus) String() string {
	switch r {
	case ReconUnknown:
		return "unknown"
	case ReconEmpty:
		return "empty"
	case ReconPartial:
		return "partial"
	case ReconComplete:
		return "complete"
	case ReconGap:
		return "gap"
	default:
		return "?"
	}
}

// reconPriority — чем больше, тем «важнее» статус для агрегата.
func reconPriority(r ReconstructionStatus) int {
	switch r {
	case ReconComplete:
		return 4
	case ReconGap:
		return 3
	case ReconPartial:
		return 2
	case ReconEmpty:
		return 1
	default:
		return 0
	}
}

// --- Структуры ---

type FlowKey struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	Proto      string
}

// seqKey — идентификатор сегмента для детекта ретрансмиссий:
// пара (seq, len), чтобы не путать ресегментацию с ретрансмиссией.
type seqKey struct {
	seq uint32
	len uint32
}

type FlowStats struct {
	Key        FlowKey
	PacketsOut uint64
	BytesOut   uint64
	PacketsIn  uint64
	BytesIn    uint64
	FirstSeen  time.Time
	LastSeen   time.Time

	SYN bool
	FIN bool
	RST bool

	MSS           uint16
	WindowScale   uint8
	HasTimestamps bool
	HasSACK       bool
	MSSKnown      bool

	Retransmits uint64
	Gaps        uint64

	PID    int
	Comm   string
	Vendor string // OUI-вендор remote-стороны (для роутерного режима)

	Hostname string
	SNI      string
	ECH      bool
	JA3      string
	JA4      string

	LastPacketTime time.Time

	// Гистограмма размеров пакетов.
	SizeBucket0_64    uint64
	SizeBucket64_128  uint64
	SizeBucket128_512 uint64
	SizeBucket512_1K  uint64
	SizeBucket1K_2K   uint64
	SizeBucket2K_8K   uint64
	SizeBucket8KPlus  uint64

	// Гистограмма интервалов.
	IntervalBucket0_1ms    uint64
	IntervalBucket1_10ms   uint64
	IntervalBucket10_100ms uint64
	IntervalBucket100ms_1s uint64
	IntervalBucket1_10s    uint64
	IntervalBucket10sPlus  uint64

	// VPN-детект.
	VPNProto string // "WireGuard" / "OpenVPN" / "IKEv2" / "obfs?" / ""
	VPNPort  uint16
	VPNConf  string // "high" / "medium" / "low"
	VPNSent  bool

	Class Classification

	// Timeline: пакеты по секундам, слот = секунда эпохи % 60.
	Timeline    [timelineSlots]uint64
	TimelineSet int64 // последняя секунда с пакетом (валидность слотов)

	// Детект ретрансмиссий (только TCP, outbound-сегменты с данными).
	seenSeq    map[seqKey]struct{}
	highestSeq uint32
	seqInit    bool

	// Аккумулятор payload для SNI из фрагментированного ClientHello.
	pendingPayload []byte
	sniExtracted   bool

	Recon ReconstructionStatus

	Route netmap.RouteInfo
}

// AggregatedFlow — суммарная статистика по SNI (или remote IP).
type AggregatedFlow struct {
	Label    string // SNI, hostname или remote IP
	Process  string // "icecat(1963)" / "192.168.1.42 (Xiaomi)" / IP
	Proto    string
	SNI      string // настоящий SNI группы (не label)
	Hostname string // rDNS-имя remote-хоста (не путать с SNI)

	Connections int
	PacketsOut  uint64
	BytesOut    uint64
	PacketsIn   uint64
	BytesIn     uint64

	FirstSeen time.Time
	LastSeen  time.Time

	Retransmits uint64
	Gaps        uint64

	MSS      uint16
	WS       uint8
	MSSKnown bool
	ECH      bool

	Recon    ReconstructionStatus
	Class    Classification
	Route    netmap.RouteInfo
	JA3      string
	JA4      string
	VPNProto string
	VPNConf  string
}

// AggregatedApp — суммарная статистика по приложению/устройству.
type AggregatedApp struct {
	Process  string
	Display  string // "192.168.1.42 Xiaomi" или "icecat(1963)"
	IP       string // для device-режима
	MAC      string
	Vendor   string
	Hostname string

	Connections int
	Domains     int
	TopDomains  []string // топ-5

	Direct  int
	Proxy   int
	VPN     int
	Unknown int

	PacketsOut uint64
	BytesOut   uint64
	PacketsIn  uint64
	BytesIn    uint64
	FirstSeen  time.Time
	LastSeen   time.Time
}

// DeviceInfo — информация об устройстве LAN.
type DeviceInfo struct {
	IP        string
	MAC       string
	Vendor    string
	Hostname  string
	FirstSeen time.Time
	LastSeen  time.Time

	Conns     int
	Domains   int
	Protocols map[string]bool

	BytesOut uint64
	BytesIn  uint64
}

type TCPFlags struct {
	SYN, ACK, FIN, RST, PSH bool

	MSS           uint16
	WindowScale   uint8
	HasTimestamps bool
	HasSACK       bool

	Payload []byte
}

// --- FlowTable ---

type FlowTable struct {
	mu         sync.Mutex
	flows      map[FlowKey]*FlowStats
	resolver   *dns.Resolver
	arpTable   map[string]string
	anomaly    *AnomalyDetector
	dnsMapping *DNSMapping

	minPkts    int
	hideIdle   bool
	activeOnly int
	appFilter  string

	vpnIPs        map[string]bool
	localMACs     map[string]string
	localHostname string

	groupByDevice bool

	lastSweep time.Time
}

func NewFlowTable() *FlowTable {
	return &FlowTable{
		flows:     make(map[FlowKey]*FlowStats),
		resolver:  dns.NewResolver(),
		arpTable:  make(map[string]string),
		vpnIPs:    make(map[string]bool),
		localMACs: make(map[string]string),
	}
}

// Close останавливает resolver и освобождает ресурсы.
func (ft *FlowTable) Close() {
	if ft.resolver != nil {
		ft.resolver.Close()
	}
}

// --- Конфигурация ---

func (ft *FlowTable) SetMinPkts(n int)    { ft.mu.Lock(); ft.minPkts = n; ft.mu.Unlock() }
func (ft *FlowTable) SetHideIdle(v bool)  { ft.mu.Lock(); ft.hideIdle = v; ft.mu.Unlock() }
func (ft *FlowTable) SetActiveOnly(n int) { ft.mu.Lock(); ft.activeOnly = n; ft.mu.Unlock() }

func (ft *FlowTable) SetAppFilter(s string) {
	// Единственный сеттер, писавший без лока — гонка с AggregateByApp.
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.appFilter = s
}

func (ft *FlowTable) SetLocalHostname(h string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.localHostname = h
}

func (ft *FlowTable) SetGroupByDevice(v bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.groupByDevice = v
}

func (ft *FlowTable) SetLocalMACs(macs map[string]string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.localMACs = macs
}

// view — снимок конфигурации и справочников для работы вне лока
// (arpTable/localMACs пишутся из Enrich — читать их без копии нельзя).
type view struct {
	minPkts       int
	hideIdle      bool
	activeOnly    int
	appFilter     string
	groupByDevice bool
	localHostname string
	arpTable      map[string]string
	localMACs     map[string]string
}

func (ft *FlowTable) currentView() view {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	v := view{
		minPkts:       ft.minPkts,
		hideIdle:      ft.hideIdle,
		activeOnly:    ft.activeOnly,
		appFilter:     ft.appFilter,
		groupByDevice: ft.groupByDevice,
		localHostname: ft.localHostname,
	}
	v.arpTable = copyMap(ft.arpTable)
	v.localMACs = copyMap(ft.localMACs)
	return v
}

func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// --- Горячий путь ---

func (ft *FlowTable) Update(srcIP string, srcPort uint16, dstIP string, dstPort uint16,
	proto string, length int, isOutbound bool, tf TCPFlags, seq uint32) {

	// Нормализация: локальная сторона — сторона инициатора.
	var key FlowKey
	if isOutbound {
		key = FlowKey{LocalIP: srcIP, LocalPort: srcPort, RemoteIP: dstIP, RemotePort: dstPort, Proto: proto}
	} else {
		key = FlowKey{LocalIP: dstIP, LocalPort: dstPort, RemoteIP: srcIP, RemotePort: srcPort, Proto: proto}
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := time.Now()
	f, ok := ft.flows[key]
	if !ok {
		f = &FlowStats{
			Key:       key,
			FirstSeen: now,
			Recon:     ReconUnknown,
			Class:     ClassUnknown,
		}
		// Remote IP — известная VPN-нода: сразу VPN.
		if ft.vpnIPs[key.RemoteIP] {
			f.Class = ClassVPN
		}
		ft.flows[key] = f
	}
	f.LastSeen = now

	f.trackTiming(now, length)
	f.trackTimeline(now.Unix())

	if isOutbound {
		f.PacketsOut++
		f.BytesOut += uint64(length)
		// Ретрансмиссии/гэпы — только TCP: у UDP seq всегда 0,
		// и равные по длине пакеты считались ретрансмиссиями из воздуха.
		if key.Proto == protoTCP {
			f.trackOutbound(tf, seq)
		}
	} else {
		f.PacketsIn++
		f.BytesIn += uint64(length)
	}

	f.SYN = f.SYN || tf.SYN
	f.FIN = f.FIN || tf.FIN
	f.RST = f.RST || tf.RST
}

// trackTiming обновляет гистограммы интервалов и размеров (под mu).
func (f *FlowStats) trackTiming(now time.Time, length int) {
	if !f.LastPacketTime.IsZero() {
		switch gap := now.Sub(f.LastPacketTime); {
		case gap < time.Millisecond:
			f.IntervalBucket0_1ms++
		case gap < 10*time.Millisecond:
			f.IntervalBucket1_10ms++
		case gap < 100*time.Millisecond:
			f.IntervalBucket10_100ms++
		case gap < time.Second:
			f.IntervalBucket100ms_1s++
		case gap < 10*time.Second:
			f.IntervalBucket1_10s++
		default:
			f.IntervalBucket10sPlus++
		}
	}
	f.LastPacketTime = now

	switch {
	case length <= 64:
		f.SizeBucket0_64++
	case length <= 128:
		f.SizeBucket64_128++
	case length <= 512:
		f.SizeBucket128_512++
	case length <= 1024:
		f.SizeBucket512_1K++
	case length <= 2048:
		f.SizeBucket1K_2K++
	case length <= 8192:
		f.SizeBucket2K_8K++
	default:
		f.SizeBucket8KPlus++
	}
}

// trackTimeline ведёт счётчики пакетов по секундам (под mu).
func (f *FlowStats) trackTimeline(curSec int64) {
	if f.TimelineSet == 0 {
		f.TimelineSet = curSec
	}
	if curSec != f.TimelineSet {
		if curSec-f.TimelineSet >= timelineSlots {
			// Всё окно устарело — быстрее обнулить целиком,
			// чем гонять цикл по каждой секунде простоя.
			f.Timeline = [timelineSlots]uint64{}
		} else {
			for s := f.TimelineSet + 1; s <= curSec; s++ {
				f.Timeline[s%timelineSlots] = 0
			}
		}
		f.TimelineSet = curSec
	}
	f.Timeline[curSec%timelineSlots]++
}

// trackOutbound — ретрансмиссии и гэпы по outbound-сегментам с данными
// (только TCP, под mu).
func (f *FlowStats) trackOutbound(tf TCPFlags, seq uint32) {
	if !f.MSSKnown && tf.MSS != 0 {
		f.MSS = tf.MSS
		f.WindowScale = tf.WindowScale
		f.HasTimestamps = tf.HasTimestamps
		f.HasSACK = tf.HasSACK
		f.MSSKnown = true
	}

	payloadLen := uint32(len(tf.Payload))
	if tf.SYN || tf.FIN || tf.RST || payloadLen == 0 {
		return
	}

	if f.seenSeq == nil {
		f.seenSeq = make(map[seqKey]struct{})
	}
	// Предел карты seq: память важнее точности счётчика ретраев
	// на гигабайтных передачах.
	if len(f.seenSeq) >= maxTrackedSeqs {
		f.seenSeq = make(map[seqKey]struct{})
	}

	k := seqKey{seq, payloadLen}
	if _, seen := f.seenSeq[k]; seen {
		f.Retransmits++
	} else {
		f.seenSeq[k] = struct{}{}
		// Гэп: сегмент начинается за концом уже виденного потока.
		// int32-дельта корректна через wraparound seq (~4 ГБ).
		if f.seqInit && int32(seq-f.highestSeq) > 0 {
			f.Gaps++
		}
	}

	if delta := int32(seq + payloadLen - f.highestSeq); delta > 0 {
		f.highestSeq = seq + payloadLen
	}
	f.seqInit = true
}

// --- SNI ---

// SetSNI устанавливает SNI напрямую (например, из QUIC Initial).
func (ft *FlowTable) SetSNI(key FlowKey, sni string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f, ok := ft.flows[key]; ok && f.SNI == "" {
		f.SNI = sni
		f.Recon = ReconComplete
	}
}

// AppendPayload аккумулирует payload потока (ClientHello может быть
// фрагментирован) и пытается извлечь SNI. Возвращает найденный SNI (или "").
func (ft *FlowTable) AppendPayload(key FlowKey, payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	f, ok := ft.flows[key]
	if !ok || f.sniExtracted {
		return ""
	}

	f.pendingPayload = append(f.pendingPayload, payload...)
	if len(f.pendingPayload) > maxClientHello {
		f.pendingPayload = f.pendingPayload[:maxClientHello]
	}

	sni := extractSNI(f.pendingPayload)
	if sni == "" {
		return ""
	}

	if sni == ECHSentinel {
		f.ECH = true
		f.SNI = ""
	} else {
		f.SNI = sni
	}
	f.sniExtracted = true
	f.Recon = ReconComplete

	// JA3/JA4 — отпечатки клиента по тому же ClientHello.
	if f.JA3 == "" {
		f.JA3 = extractJA3(f.pendingPayload)
	}
	if f.JA4 == "" {
		f.JA4 = extractJA4(f.pendingPayload)
	}
	f.pendingPayload = nil
	return sni
}

// --- Enrichment ---

// Enrich привязывает процессы, имена, маршруты и классификацию.
// Дорогой I/O (rDNS, маршруты) вынесен из-под лока — раньше горутина
// пакетов стояла на время сетевых таймаутов. Заодно lookup'ы делаются
// по уникальным IP, а не по каждому потоку.
func (ft *FlowTable) Enrich() {
	// Сканирование окружения — вне лока.
	socketsByTuple, _ := proc.ScanSockets()
	socketsByPort, _ := proc.ScanSocketsByLocalPort()
	inodes, _ := proc.MapInodesToPIDs()
	arp := proc.ScanARP()

	// Фаза 1 (под локом): привязка процессов, вычистка, сбор работы.
	ft.mu.Lock()

	ft.arpTable = arp
	ft.sweepLocked(time.Now())

	needHostname := make(map[string]bool)
	needRoute := make(map[string]bool)
	needSNI := make(map[string]bool)
	var work []FlowKey

	for key, f := range ft.flows {
		if f.Comm == "" {
			tupleKey := proc.SocketKey{
				LocalIP:    f.Key.LocalIP,
				LocalPort:  f.Key.LocalPort,
				RemoteIP:   f.Key.RemoteIP,
				RemotePort: f.Key.RemotePort,
			}
			inode, ok := socketsByTuple[tupleKey]
			if !ok {
				// Fallback по локальному порту: неточен (порт могли
				// переиспользовать), но лучше, чем ничего.
				inode, ok = socketsByPort[f.Key.LocalPort]
			}
			if ok {
				if info, ok := inodes[inode]; ok {
					f.PID = info.PID
					f.Comm = info.Comm
				}
			}
		}

		touch := false
		if f.Hostname == "" && f.Key.RemoteIP != "" {
			needHostname[f.Key.RemoteIP] = true
			touch = true
		}
		if f.Route.Interface == "" && f.Key.RemoteIP != "" {
			needRoute[f.Key.RemoteIP] = true
			touch = true
		}
		if f.Class == ClassUnknown && f.SNI != "" { // ← добавили
			needSNI[f.SNI] = true
			touch = true
		}
		if f.Class == ClassUnknown {
			touch = true
		}
		if touch {
			work = append(work, key)
		}
	}
	ft.mu.Unlock()

	if len(work) == 0 {
		return
	}

	// Фаза 2 (без лока): сетевые запросы по уникальным IP.
	hostnames := make(map[string]string, len(needHostname))
	for ip := range needHostname {
		hostnames[ip] = ft.resolver.Lookup(ip)
	}
	routes := make(map[string]netmap.RouteInfo, len(needRoute))
	for ip := range needRoute {
		routes[ip] = netmap.LookupRoute(ip)
	}

	// ClassifyFlow → resolveSNIAt → net.LookupIP — блокирующий DNS,
	// а фаза 3 идёт под ft.mu. Прогреваем кэш заранее.
	for sni := range needSNI {
		resolveSNI(sni)
	}
	// Фаза 3 (под локом): применяем и классифицируем.
	ft.mu.Lock()
	defer ft.mu.Unlock()

	for _, key := range work {
		f, ok := ft.flows[key]
		if !ok {
			continue
		}

		if f.Hostname == "" {
			f.Hostname = hostnames[f.Key.RemoteIP]
		}
		if f.Route.Interface == "" {
			f.Route = routes[f.Key.RemoteIP]
		}

		// Прокси-процесс + SNI не резолвится → это прокси-фронт, не VPN.
		// vpnIPs НЕ пополняется здесь (см. пункт 4.4 ревью).
		if f.Class == ClassUnknown && f.Comm != "" &&
			looksLikeProxyProcess(f.Comm) && f.SNI != "" {
			res := resolveSNIAt(f.SNI, f.Key.RemoteIP, f.LastSeen, ft.dnsMapping)
			if res.Reason == "not-resolved" {
				f.Class = ClassProxy
			}
		}
		if f.Class == ClassUnknown {
			f.Class = ClassifyFlow(f, ft.dnsMapping)
		}
	}
}

// sweepLocked вычищает давно неактивные потоки: без этого ft.flows
// и seenSeq внутри них растут бесконечно (вызывается под mu).
func (ft *FlowTable) sweepLocked(now time.Time) {
	if now.Sub(ft.lastSweep) < flowSweepEvery {
		return
	}
	ft.lastSweep = now

	cutoff := now.Add(-flowMaxAge)
	for key, f := range ft.flows {
		if f.LastSeen.Before(cutoff) {
			delete(ft.flows, key)
		}
	}
}

// Snapshot возвращает копию потоков, свежие сверху.
func (ft *FlowTable) Snapshot() []FlowStats {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	out := make([]FlowStats, 0, len(ft.flows))
	for _, f := range ft.flows {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// --- Агрегация ---

// Aggregate группирует потоки по SNI/hostname/IP.
func (ft *FlowTable) Aggregate() []AggregatedFlow {
	return ft.aggregateFrom(ft.Snapshot())
}

func (ft *FlowTable) aggregateFrom(flows []FlowStats) []AggregatedFlow {
	v := ft.currentView()

	groups := make(map[string]*AggregatedFlow)

	for i := range flows {
		f := &flows[i]

		// LAN-трафик для аудита не интересен.
		if isLANIP(f.Key.RemoteIP) {
			continue
		}

		label := f.SNI
		if label == "" && f.Hostname != "" {
			// 1e100.net — «безымянные» хосты Google: IP информативнее.
			if !strings.HasSuffix(f.Hostname, ".1e100.net") {
				label = f.Hostname
			}
		}
		if label == "" {
			label = f.Key.RemoteIP
		}

		// Пометка о неполной реконструкции — только TCP/443.
		if f.Key.Proto == protoTCP && f.Key.RemotePort == portHTTPS {
			switch f.Recon {
			case ReconGap:
				label += " ⚠gap"
			case ReconPartial:
				label += " ⚠partial"
			}
		}

		process := f.Key.LocalIP
		if f.Comm != "" {
			process = fmt.Sprintf("%s(%d)", f.Comm, f.PID)
		} else if mac, ok := v.arpTable[f.Key.LocalIP]; ok {
			process = fmt.Sprintf("%s (%s)", f.Key.LocalIP, proc.DescribeMAC(mac))
		}

		key := label + "|" + process + "|" + f.Key.Proto

		g, ok := groups[key]
		if !ok {
			g = &AggregatedFlow{
				Label:     label,
				Process:   process,
				Proto:     f.Key.Proto,
				FirstSeen: f.FirstSeen,
			}
			groups[key] = g
		}

		if g.SNI == "" {
			g.SNI = f.SNI
		}
		if g.Hostname == "" {
			g.Hostname = f.Hostname
		}

		g.Connections++
		g.PacketsOut += f.PacketsOut
		g.BytesOut += f.BytesOut
		g.PacketsIn += f.PacketsIn
		g.BytesIn += f.BytesIn
		g.Retransmits += f.Retransmits
		g.Gaps += f.Gaps
		if g.VPNProto == "" && f.VPNProto != "" {
			g.VPNProto = f.VPNProto
			g.VPNConf = f.VPNConf
		}

		if reconPriority(f.Recon) > reconPriority(g.Recon) {
			g.Recon = f.Recon
		}
		if classPriority(f.Class) > classPriority(g.Class) {
			g.Class = f.Class
		}

		g.ECH = g.ECH || f.ECH
		if g.JA3 == "" {
			g.JA3 = f.JA3
		}
		if g.JA4 == "" {
			g.JA4 = f.JA4
		}
		if g.SNI == "" {
			g.SNI = f.SNI
		}
		if g.Hostname == "" {
			g.Hostname = f.Hostname
		}
		if f.LastSeen.After(g.LastSeen) {
			g.LastSeen = f.LastSeen
		}
		if f.FirstSeen.Before(g.FirstSeen) {
			g.FirstSeen = f.FirstSeen
		}
		if !g.MSSKnown && f.MSSKnown {
			g.MSS = f.MSS
			g.WS = f.WindowScale
			g.MSSKnown = true
		}
		if g.Route.Interface == "" && f.Route.Interface != "" {
			g.Route = f.Route
		}
	}

	out := make([]AggregatedFlow, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// --- Вывод ---

// isNoisyGroup — keep-alive-подобные группы: медленно и мелко, либо
// давно затихшие и крошечные. Прежний isNoisy был мёртвым кодом,
// а его логика дублировалась в Print инлайном.
func isNoisyGroup(g AggregatedFlow, now time.Time) bool {
	totalPkts := g.PacketsOut + g.PacketsIn
	if totalPkts == 0 {
		return true
	}
	totalBytes := g.BytesOut + g.BytesIn

	ageSec := now.Sub(g.FirstSeen).Seconds()
	if ageSec <= 0 {
		ageSec = 1
	}
	pktPerSec := float64(totalPkts) / ageSec
	avgSize := float64(totalBytes) / float64(totalPkts)

	// Классический keep-alive: медленно и маленькими пакетами.
	if pktPerSec < noiseMaxRate && avgSize < noiseMaxAvg {
		return true
	}
	// Затихший поток: активность давно, объём крошечный.
	return now.Sub(g.LastSeen) > noiseIdleAfter && totalBytes < noiseMaxBytes
}

func (ft *FlowTable) Print() {
	v := ft.currentView()
	allGroups := ft.Aggregate()

	groups := make([]AggregatedFlow, 0, len(allGroups))
	var hiddenByPkts, hiddenByIdle, hiddenByActive, hiddenByNoise int
	now := time.Now()

	for _, g := range allGroups {
		totalPkts := g.PacketsOut + g.PacketsIn

		if v.minPkts > 0 && totalPkts < uint64(v.minPkts) {
			hiddenByPkts++
			continue
		}
		if v.hideIdle && now.Sub(g.LastSeen) > idleHideAfter {
			hiddenByIdle++
			continue
		}
		if v.activeOnly > 0 && now.Sub(g.LastSeen) > time.Duration(v.activeOnly)*time.Second {
			hiddenByActive++
			continue
		}
		if isNoisyGroup(g, now) {
			hiddenByNoise++
			continue
		}
		groups = append(groups, g)
	}

	if len(groups) == 0 {
		fmt.Printf("\n=== Групп нет (скрыто: %d pkts / %d idle / %d active / %d шум) ===\n",
			hiddenByPkts, hiddenByIdle, hiddenByActive, hiddenByNoise)
		return
	}

	fmt.Printf("\n=== Группы по SNI (%d", len(groups))
	if hidden := hiddenByPkts + hiddenByIdle + hiddenByActive + hiddenByNoise; hidden > 0 {
		fmt.Printf(", скрыто: %d pkts / %d idle / %d active / %d шум",
			hiddenByPkts, hiddenByIdle, hiddenByActive, hiddenByNoise)
	}
	fmt.Printf(") ===\n")

	fmt.Printf("%-28s %-32s %-7s %-8s %-12s %-5s %5s %8s %8s %10s %10s %4s %4s %5s\n",
		"PROCESS", "SNI / REMOTE", "RECON", "CLASS", "ROUTE", "PROTO", "CONNS", "PKT/S", "AVG_SZ", "OUT", "IN", "RETR", "GAPS", "AGE")

	for _, g := range groups {
		age := time.Since(g.FirstSeen)
		ageSec := age.Seconds()
		totalPkts := g.PacketsOut + g.PacketsIn
		totalBytes := g.BytesOut + g.BytesIn

		var pktPerSec, avgSize float64
		if ageSec > 0 {
			pktPerSec = float64(totalPkts) / ageSec
		}
		if totalPkts > 0 {
			avgSize = float64(totalBytes) / float64(totalPkts)
		}

		reconStr := "—"
		if g.Proto == protoTCP {
			if g.ECH {
				reconStr = "ech"
			} else {
				switch g.Recon {
				case ReconComplete:
					reconStr = "✓"
				case ReconPartial:
					reconStr = "⚠part"
				case ReconGap:
					reconStr = "⚠gap"
				case ReconEmpty:
					reconStr = "·"
				case ReconUnknown:
					reconStr = "?"
				}
			}
		}
		routeStr := g.Route.Interface
		if routeStr == "" {
			routeStr = "—"
		}

		fmt.Printf("%-28s %-32s %-7s %-8s %-12s %-5s %5d %8.1f %8.0f %10s %10s %4d %4d %5s\n",
			truncate(g.Process, 28),
			truncate(g.Label, 32),
			reconStr,
			g.Class.String(),
			truncate(routeStr, 12),
			g.Proto,
			g.Connections,
			pktPerSec,
			avgSize,
			humanBytes(g.BytesOut),
			humanBytes(g.BytesIn),
			g.Retransmits,
			g.Gaps,
			age.Truncate(time.Second).String())
	}
	fmt.Println()
}

// PrintProfile печатает тайминг-профиль для указанного SNI.
func (ft *FlowTable) PrintProfile(matchSNI string) {
	if matchSNI == "" {
		return
	}

	var matched []FlowStats
	for _, f := range ft.Snapshot() {
		if f.SNI == matchSNI {
			matched = append(matched, f)
		}
	}
	if len(matched) == 0 {
		fmt.Printf("\n=== Профиль для %q: потоков не найдено ===\n", matchSNI)
		return
	}

	var (
		intervalBuckets [6]uint64
		sizeBuckets     [7]uint64
		timeline        [timelineSlots]uint64
		totalBytesOut   uint64
		totalBytesIn    uint64
		totalPkts       uint64
	)

	now := time.Now().Unix()

	for _, f := range matched {
		intervalBuckets[0] += f.IntervalBucket0_1ms
		intervalBuckets[1] += f.IntervalBucket1_10ms
		intervalBuckets[2] += f.IntervalBucket10_100ms
		intervalBuckets[3] += f.IntervalBucket100ms_1s
		intervalBuckets[4] += f.IntervalBucket1_10s
		intervalBuckets[5] += f.IntervalBucket10sPlus

		sizeBuckets[0] += f.SizeBucket0_64
		sizeBuckets[1] += f.SizeBucket64_128
		sizeBuckets[2] += f.SizeBucket128_512
		sizeBuckets[3] += f.SizeBucket512_1K
		sizeBuckets[4] += f.SizeBucket1K_2K
		sizeBuckets[5] += f.SizeBucket2K_8K
		sizeBuckets[6] += f.SizeBucket8KPlus

		// Слот актуален только для секунд <= TimelineSet: слоты ПОСЛЕ
		// последнего пакета не обнулены и хранят данные минутной
		// давности, маскируясь под свежую активность.
		for i := 0; i < timelineSlots; i++ {
			sec := now - 59 + int64(i)
			if sec > f.TimelineSet {
				continue
			}
			timeline[i] += f.Timeline[sec%timelineSlots]
		}

		totalBytesOut += f.BytesOut
		totalBytesIn += f.BytesIn
		totalPkts += f.PacketsOut + f.PacketsIn
	}

	fmt.Printf("\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Тайминг-профиль: %-43s ║\n", matchSNI)
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("  Потоков: %d   Пакетов: %d   OUT: %s   IN: %s\n\n",
		len(matched), totalPkts, humanBytes(totalBytesOut), humanBytes(totalBytesIn))

	fmt.Println("  ── Интервалы между пакетами ──")
	printHistogram("  <1ms       ", intervalBuckets[0], totalPkts)
	printHistogram("  1-10ms     ", intervalBuckets[1], totalPkts)
	printHistogram("  10-100ms   ", intervalBuckets[2], totalPkts)
	printHistogram("  100ms-1s   ", intervalBuckets[3], totalPkts)
	printHistogram("  1-10s      ", intervalBuckets[4], totalPkts)
	printHistogram("  >10s       ", intervalBuckets[5], totalPkts)

	fmt.Println()
	fmt.Println("  ── Размеры пакетов ──")
	printHistogram("  0-64 B     ", sizeBuckets[0], totalPkts)
	printHistogram("  64-128 B   ", sizeBuckets[1], totalPkts)
	printHistogram("  128-512 B  ", sizeBuckets[2], totalPkts)
	printHistogram("  512B-1K    ", sizeBuckets[3], totalPkts)
	printHistogram("  1K-2K      ", sizeBuckets[4], totalPkts)
	printHistogram("  2K-8K      ", sizeBuckets[5], totalPkts)
	printHistogram("  >8K        ", sizeBuckets[6], totalPkts)

	fmt.Println()
	fmt.Println("  ── Timeline (последние 60 сек, слева = старая) ──")
	maxVal := uint64(0)
	for i := 0; i < timelineSlots; i++ {
		if timeline[i] > maxVal {
			maxVal = timeline[i]
		}
	}
	if maxVal == 0 {
		fmt.Println("  (нет данных)")
	} else {
		fmt.Print("  ")
		for i := 0; i < timelineSlots; i++ {
			sec := now - 59 + int64(i)
			val := timeline[sec%timelineSlots]
			if val == 0 {
				fmt.Print(" ")
				continue
			}
			switch ratio := float64(val) / float64(maxVal); {
			case ratio < 0.2:
				fmt.Print(".")
			case ratio < 0.4:
				fmt.Print(":")
			case ratio < 0.6:
				fmt.Print("|")
			case ratio < 0.8:
				fmt.Print("H")
			default:
				fmt.Print("#")
			}
		}
		fmt.Println()
		fmt.Printf("  (max: %d пакетов/сек)\n", maxVal)
	}
	fmt.Println()
}

// printHistogram печатает одну строку гистограммы.
func printHistogram(label string, count, total uint64) {
	if total == 0 {
		fmt.Printf("%s %8d\n", label, count)
		return
	}
	pct := float64(count) / float64(total) * 100
	barLen := int(pct / 2)
	if barLen > maxBarLen {
		barLen = maxBarLen
	}
	fmt.Printf("%s %8d  %5.1f%%  %s\n", label, count, pct, strings.Repeat("█", barLen))
}

// AggregateByApp группирует потоки по процессу (или устройству).
func (ft *FlowTable) AggregateByApp() []AggregatedApp {
	return ft.aggregateByAppFrom(ft.Snapshot())
}

func (ft *FlowTable) aggregateByAppFrom(flows []FlowStats) []AggregatedApp {
	v := ft.currentView()

	type classCounts struct{ direct, proxy, vpn, unknown int }

	groups := make(map[string]*AggregatedApp)
	domainsByApp := make(map[string]map[string]int)
	classesByApp := make(map[string]*classCounts)

	for i := range flows {
		f := &flows[i]

		// LAN-трафик для аудита не интересен.
		if isLANIP(f.Key.RemoteIP) {
			continue
		}

		var process, display, ip, mac, vendor string

		if v.groupByDevice {
			// device-режим: группировка по IP устройства.
			ip = f.Key.LocalIP
			process = ip

			mac = v.arpTable[ip]
			if mac == "" {
				mac = v.localMACs[ip]
			}
			if mac != "" {
				vendor = proc.DescribeMAC(mac)
			}

			display = ip
			if vendor != "" && vendor != "unknown" {
				display += " " + vendor
			}
			// Hostname устройства по PTR удалённого хоста не
			// восстанавливается — раньше f.Hostname (rDNS REMOTE)
			// ошибочно писался как имя устройства.
		} else {
			// app-режим.
			if f.Comm != "" {
				process = fmt.Sprintf("%s(%d)", f.Comm, f.PID)
			} else if m, ok := v.arpTable[f.Key.LocalIP]; ok {
				process = fmt.Sprintf("%s (%s)", f.Key.LocalIP, proc.DescribeMAC(m))
			} else {
				process = f.Key.LocalIP
			}
			display = process
		}

		if v.appFilter != "" && !strings.Contains(display, v.appFilter) {
			continue
		}

		g, ok := groups[process]
		if !ok {
			g = &AggregatedApp{
				Process:   process,
				Display:   display,
				IP:        ip,
				MAC:       mac,
				Vendor:    vendor,
				FirstSeen: f.FirstSeen,
			}
			groups[process] = g
			domainsByApp[process] = make(map[string]int)
			classesByApp[process] = &classCounts{}
		}

		g.Connections++
		g.PacketsOut += f.PacketsOut
		g.BytesOut += f.BytesOut
		g.PacketsIn += f.PacketsIn
		g.BytesIn += f.BytesIn

		if f.LastSeen.After(g.LastSeen) {
			g.LastSeen = f.LastSeen
		}
		if f.FirstSeen.Before(g.FirstSeen) {
			g.FirstSeen = f.FirstSeen
		}

		label := f.SNI
		if label == "" {
			label = f.Hostname
		}
		if label == "" {
			label = f.Key.RemoteIP
		}
		domainsByApp[process][label]++

		cc := classesByApp[process]
		switch f.Class {
		case ClassDirect:
			cc.direct++
		case ClassProxy:
			cc.proxy++
		case ClassVPN:
			cc.vpn++
		default:
			cc.unknown++
		}
	}

	out := make([]AggregatedApp, 0, len(groups))
	for name, g := range groups {
		g.Domains = len(domainsByApp[name])

		// Топ-5 доменов по числу потоков; при равенстве — по алфавиту,
		// чтобы вывод не прыгал между циклами печати.
		type kv struct {
			k string
			v int
		}
		pairs := make([]kv, 0, len(domainsByApp[name]))
		for k, cnt := range domainsByApp[name] {
			pairs = append(pairs, kv{k, cnt})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].v != pairs[j].v {
				return pairs[i].v > pairs[j].v
			}
			return pairs[i].k < pairs[j].k
		})
		for i, p := range pairs {
			if i >= 5 {
				break
			}
			g.TopDomains = append(g.TopDomains, p.k)
		}

		cc := classesByApp[name]
		g.Direct, g.Proxy, g.VPN, g.Unknown = cc.direct, cc.proxy, cc.vpn, cc.unknown

		out = append(out, *g)
	}

	// Сверху — самые «тяжёлые».
	sort.Slice(out, func(i, j int) bool {
		return out[i].BytesIn+out[i].BytesOut > out[j].BytesIn+out[j].BytesOut
	})
	return out
}

// PrintApps выводит таблицу приложений/устройств.
func (ft *FlowTable) PrintApps() {
	v := ft.currentView()
	apps := ft.AggregateByApp()
	if len(apps) == 0 {
		return
	}

	title := "Приложения"
	if v.groupByDevice {
		title = "Устройства"
	}

	fmt.Printf("\n=== %s (%d) ===\n", title, len(apps))

	if v.groupByDevice {
		fmt.Printf("%-16s %-18s %-14s %6s %6s %5s %5s %5s %10s %10s %6s\n",
			"IP", "MAC", "HOSTNAME", "CONNS", "DOMAINS", "DIR", "PRX", "VPN", "OUT", "IN", "AGE")
	} else {
		fmt.Printf("%-28s %6s %6s %5s %5s %5s %10s %10s %6s\n",
			"APP", "CONNS", "DOMAINS", "DIR", "PRX", "VPN", "OUT", "IN", "AGE")
	}

	for _, a := range apps {
		age := time.Since(a.FirstSeen).Truncate(time.Second)

		if v.groupByDevice {
			mac := a.MAC
			if mac == "" {
				mac = "—"
			}
			hostname := a.Hostname
			if hostname == "" {
				hostname = "—"
			}
			fmt.Printf("%-16s %-18s %-14s %6d %6d %5d %5d %5d %10s %10s %6s\n",
				truncate(a.IP, 16),
				truncate(mac, 18),
				truncate(hostname, 14),
				a.Connections,
				a.Domains,
				a.Direct,
				a.Proxy,
				a.VPN,
				humanBytes(a.BytesOut),
				humanBytes(a.BytesIn),
				age.String())
		} else {
			fmt.Printf("%-28s %6d %6d %5d %5d %5d %10s %10s %6s\n",
				truncate(a.Display, 28),
				a.Connections,
				a.Domains,
				a.Direct,
				a.Proxy,
				a.VPN,
				humanBytes(a.BytesOut),
				humanBytes(a.BytesIn),
				age.String())
		}
	}
	fmt.Println()
}

// --- Поиск процессов ---

// FindProcessByIP ищет процесс с потоком к указанному IP.
func (ft *FlowTable) FindProcessByIP(ip string) string {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	for _, f := range ft.flows {
		if f.Key.RemoteIP == ip && f.Comm != "" {
			return fmt.Sprintf("%s(%d)", f.Comm, f.PID)
		}
	}
	return ""
}

// FindProcessByDomain ищет процесс по SNI-имени.
func (ft *FlowTable) FindProcessByDomain(domain string) string {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	for _, f := range ft.flows {
		if f.SNI == domain && f.Comm != "" {
			return fmt.Sprintf("%s(%d)", f.Comm, f.PID)
		}
	}
	return ""
}

// --- VPN / классификация ---

// MarkVPN фиксирует результат детектора и запоминает ноду:
// все будущие потоки к этому IP классифицируются как VPN.
func (ft *FlowTable) MarkVPN(srcIP string, srcPort uint16, dstIP string, dstPort uint16,
	proto string, det *VPNDetection) {

	// Вызывается только для outbound: src — локальная сторона.
	key := FlowKey{
		LocalIP:    srcIP,
		LocalPort:  srcPort,
		RemoteIP:   dstIP,
		RemotePort: dstPort,
		Proto:      proto,
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	if f, ok := ft.flows[key]; ok && f.VPNProto == "" {
		f.VPNProto = det.Proto
		f.VPNPort = det.Port
		f.VPNConf = det.Confidence
		// ClassVPN только для high/medium.
		// low (obfs?) — эвристика по энтропии, может ложно срабатывать
		// на QUIC/DTLS/WebRTC/Telegram (см. пункт 4.4 ревью).
		if det.Confidence != "low" {
			f.Class = ClassVPN
		}
	}

	if ft.vpnIPs == nil {
		ft.vpnIPs = make(map[string]bool)
	}
	if det.Confidence != "low" {
		ft.vpnIPs[dstIP] = true
	}
}

// ClassifyFlow определяет итоговую классификацию потока.
// mapping используется для проверки SNI ↔ DNS; может быть nil.
func ClassifyFlow(f *FlowStats, mapping *DNSMapping) Classification {
	// ECH: SNI скрыт, но это не признак прокси.
	if f.ECH {
		return ClassDirect
	}
	// VPN-детектор сработал.
	if f.VPNProto != "" && f.VPNConf != "low" {
		return ClassVPN
	}
	// Прокси-процесс без SNI.
	if looksLikeProxyProcess(f.Comm) && f.SNI == "" {
		return ClassProxy
	}

	if f.SNI != "" {
		res := resolveSNIAt(f.SNI, f.Key.RemoteIP, f.LastSeen, mapping)
		switch res.Reason {
		case "matched":
			return ClassDirect
		case "not-resolved":
			return ClassProxy // домен не резолвится — прокси-фронт
		case "different-ip":
			return ClassDirect // CDN-балансировка, не прокси
		case "no-observation":
			if len(res.ObservedIPs) > 0 {
				return ClassDirect // резолвится, просто сам ответ не видели
			}
		}
	}

	return ClassUnknown
}

// --- Устройства LAN ---

// BuildDevices собирает LAN-клиентов (не роутер) из flows.
func (ft *FlowTable) BuildDevices() []DeviceInfo {
	return ft.buildDevicesFrom(ft.Snapshot())
}

func (ft *FlowTable) buildDevicesFrom(flows []FlowStats) []DeviceInfo {
	v := ft.currentView()

	devices := make(map[string]*DeviceInfo)
	domainsByIP := make(map[string]map[string]bool)
	protocolsByIP := make(map[string]map[string]bool)

	for i := range flows {
		f := &flows[i]

		// Только LAN-клиенты, только трафик в интернет.
		if !isLANIP(f.Key.LocalIP) || isLANIP(f.Key.RemoteIP) {
			continue
		}

		ip := f.Key.LocalIP
		d, ok := devices[ip]
		if !ok {
			// MAC: сначала ARP, потом свои интерфейсы.
			mac := v.arpTable[ip]
			if mac == "" {
				mac = v.localMACs[ip]
			}
			vendor := "unknown"
			if mac != "" {
				vendor = proc.DescribeMAC(mac)
			}
			d = &DeviceInfo{
				IP:        ip,
				MAC:       mac,
				Vendor:    vendor,
				FirstSeen: f.FirstSeen,
			}
			devices[ip] = d
			domainsByIP[ip] = make(map[string]bool)
			protocolsByIP[ip] = make(map[string]bool)
		}

		d.Conns++
		d.BytesOut += f.BytesOut
		d.BytesIn += f.BytesIn

		if f.LastSeen.After(d.LastSeen) {
			d.LastSeen = f.LastSeen
		}
		if f.FirstSeen.Before(d.FirstSeen) {
			d.FirstSeen = f.FirstSeen
		}

		// Hostname: только для собственного ПК (localHostname).
		if d.Hostname == "" {
			if _, isLocal := v.localMACs[d.IP]; isLocal && v.localHostname != "" {
				d.Hostname = v.localHostname
			}
		}

		label := f.SNI
		if label == "" {
			label = f.Hostname
		}
		if label != "" {
			domainsByIP[ip][label] = true
		}
		protocolsByIP[ip][f.Key.Proto] = true
	}

	out := make([]DeviceInfo, 0, len(devices))
	for ip, d := range devices {
		d.Domains = len(domainsByIP[ip])
		d.Protocols = protocolsByIP[ip]
		out = append(out, *d)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// PrintDevices выводит таблицу устройств LAN.
func (ft *FlowTable) PrintDevices() {
	devices := ft.BuildDevices()
	if len(devices) == 0 {
		return
	}

	fmt.Printf("\n=== Устройства LAN (%d) ===\n", len(devices))
	fmt.Printf("%-16s %-18s %-16s %-14s %6s %8s %10s %10s %6s\n",
		"IP", "MAC", "VENDOR", "HOSTNAME", "CONNS", "DOMAINS", "OUT", "IN", "AGE")

	for _, d := range devices {
		mac := d.MAC
		if mac == "" {
			mac = "—"
		}
		hostname := d.Hostname
		if hostname == "" {
			hostname = "—"
		}
		age := time.Since(d.FirstSeen).Truncate(time.Second)

		fmt.Printf("%-16s %-18s %-16s %-14s %6d %8d %10s %10s %6s\n",
			truncate(d.IP, 16),
			truncate(mac, 18),
			truncate(d.Vendor, 16),
			truncate(hostname, 14),
			d.Conns,
			d.Domains,
			humanBytes(d.BytesOut),
			humanBytes(d.BytesIn),
			age.String())
	}
	fmt.Println()
}

// --- Утилиты вывода ---

// humanBytes форматирует байты в человекочитаемый вид.
func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// truncate обрезает строку до max байт, добавляя "…".
// Не рвёт UTF-8 посередине руны.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut <= 0 {
		return "…"
	}
	return s[:cut] + "…"
}
