package capture

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"digger/internal/dns"
	"digger/internal/proc"
)

type FlowKey struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	Proto      string
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

	// Timing profile
	LastPacketTime time.Time

	// Histogram размеров пакетов (по бакетам)
	SizeBucket0_64    uint64 // 0-64
	SizeBucket64_128  uint64
	SizeBucket128_512 uint64
	SizeBucket512_1K  uint64
	SizeBucket1K_2K   uint64
	SizeBucket2K_8K   uint64
	SizeBucket8KPlus  uint64

	// Histogram интервалов
	IntervalBucket0_1ms    uint64
	IntervalBucket1_10ms   uint64
	IntervalBucket10_100ms uint64
	IntervalBucket100ms_1s uint64
	IntervalBucket1_10s    uint64
	IntervalBucket10sPlus  uint64

	// Timeline: счётчики пакетов по секундам (последние 60 сек)
	// Используем массив из 60 слотов, индекс = секунда эпохи % 60
	Timeline    [60]uint64
	TimelineSet int64 // последняя секунда эпохи, для которой обновляли Timeline

	// tracking исходящих seq для retransmit detection
	seenSeq     map[uint32]struct{}
	highestSeq  uint32
	lastOutSeqEnd uint32
	seqInit       bool

	// Аккумулятор payload'а для извлечения SNI из фрагментированного ClientHello
	pendingPayload []byte
	sniExtracted   bool
}

// AggregatedFlow — суммарная статистика по SNI (или remote IP).
type AggregatedFlow struct {
	Label      string // SNI, или hostname, или remote IP
	Process    string // "icecat(1963)" или "?"
	Proto      string

	Connections int
	PacketsOut  uint64
	BytesOut    uint64
	PacketsIn   uint64
	BytesIn     uint64

	FirstSeen  time.Time
	LastSeen   time.Time

	Retransmits uint64
	Gaps        uint64

	MSS       uint16
	WS        uint8
	MSSKnown  bool
}

type FlowTable struct {
	mu       sync.Mutex
	flows    map[FlowKey]*FlowStats
	resolver *dns.Resolver
	arpTable map[string]string
	anomaly  *AnomalyDetector

	minPkts    int
	hideIdle   bool
	activeOnly int
}

func NewFlowTable() *FlowTable {
	return &FlowTable{
		flows:    make(map[FlowKey]*FlowStats),
		resolver: dns.NewResolver(),
		arpTable: make(map[string]string),
		minPkts:  0,
		hideIdle: false,
	}
}

func (ft *FlowTable) SetMinPkts(n int)    { ft.mu.Lock(); ft.minPkts = n; ft.mu.Unlock() }
func (ft *FlowTable) SetHideIdle(v bool)  { ft.mu.Lock(); ft.hideIdle = v; ft.mu.Unlock() }
func (ft *FlowTable) SetActiveOnly(n int) { ft.mu.Lock(); ft.activeOnly = n; ft.mu.Unlock() }

func (ft *FlowTable) Update(srcIP string, srcPort uint16, dstIP string, dstPort uint16,
			    proto string, length int, isOutbound bool, tf TCPFlags, seq uint32) {

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
			seenSeq:   make(map[uint32]struct{}),
		}
		ft.flows[key] = f
	}
	f.LastSeen = now

	// Timing profile: интервал с предыдущего пакета
	if !f.LastPacketTime.IsZero() {
		gap := now.Sub(f.LastPacketTime)
		switch {
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

	// Size histogram
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

	// Timeline
	curSec := now.Unix()
	if f.TimelineSet == 0 {
		f.TimelineSet = curSec
	}
	if curSec != f.TimelineSet {
		// Сдвигаем timeline вперёд: обнуляем все слоты между TimelineSet и curSec
		for s := f.TimelineSet + 1; s <= curSec; s++ {
			f.Timeline[s%60] = 0
		}
		f.TimelineSet = curSec
	}
	f.Timeline[curSec%60]++

	if isOutbound {
		f.PacketsOut++
		f.BytesOut += uint64(length)

		if !f.MSSKnown && tf.MSS != 0 {
			f.MSS = tf.MSS
			f.WindowScale = tf.WindowScale
			f.HasTimestamps = tf.HasTimestamps
			f.HasSACK = tf.HasSACK
			f.MSSKnown = true
		}

		payloadLen := uint32(len(tf.Payload))

		// Retransmit detection: только для сегментов с данными
		if !tf.SYN && !tf.FIN && !tf.RST && payloadLen > 0 {
			// Ключ — пара (seq, длина), чтобы отличить два разных сегмента с одним seq,
			// но разной длиной (что бывает при сегментации)
			if _, seen := f.seenSeq[seq]; seen {
				f.Retransmits++
			} else {
				f.seenSeq[seq] = struct{}{}

				// Gap: seq больше, чем все предыдущие + максимум виденного payload
				if f.seqInit {
					if seq > f.highestSeq+payloadLen {
						f.Gaps++
					}
				}
			}

			if seq+payloadLen > f.highestSeq {
				f.highestSeq = seq + payloadLen
			}
			f.seqInit = true
		}
	} else {
		f.PacketsIn++
		f.BytesIn += uint64(length)
	}

	if tf.SYN { f.SYN = true }
	if tf.FIN { f.FIN = true }
	if tf.RST { f.RST = true }
			    }

			    func (ft *FlowTable) SetSNI(key FlowKey, sni string) {
				    ft.mu.Lock()
				    defer ft.mu.Unlock()
				    if f, ok := ft.flows[key]; ok {
					    if f.SNI == "" {
						    f.SNI = sni
					    }
				    }
			    }

			    // AppendPayload аккумулирует payload для потока и пытается извлечь SNI.
			    // Возвращает найденный SNI (или "").
			    func (ft *FlowTable) AppendPayload(key FlowKey, payload []byte) string {
				    if len(payload) == 0 {
					    return ""
				    }

				    ft.mu.Lock()
				    defer ft.mu.Unlock()

				    f, ok := ft.flows[key]
				    if !ok {
					    return ""
				    }
				    if f.sniExtracted {
					    return ""
				    }

				    // Ограничиваем размер аккумулятора (ClientHello не должен быть больше 8KB)
				    const maxAccum = 8192
				    f.pendingPayload = append(f.pendingPayload, payload...)
				    if len(f.pendingPayload) > maxAccum {
					    f.pendingPayload = f.pendingPayload[:maxAccum]
				    }

				    if sni := extractSNI(f.pendingPayload); sni != "" {
					    f.SNI = sni
					    f.sniExtracted = true
					    f.pendingPayload = nil
					    return sni
				    }

				    return ""
			    }

			    func (ft *FlowTable) Enrich() {
				    socketsByTuple, _ := proc.ScanSockets()
				    socketsByPort, _ := proc.ScanSocketsByLocalPort()
				    inodes, _ := proc.MapInodesToPIDs()
				    arp := proc.ScanARP()

				    ft.mu.Lock()
				    defer ft.mu.Unlock()

				    ft.arpTable = arp

				    for _, f := range ft.flows {
					    if f.Comm == "" {
						    tupleKey := proc.SocketKey{
							    LocalIP:    f.Key.LocalIP,
							    LocalPort:  f.Key.LocalPort,
							    RemoteIP:   f.Key.RemoteIP,
							    RemotePort: f.Key.RemotePort,
						    }
						    inode, ok := socketsByTuple[tupleKey]
						    if !ok {
							    inode, ok = socketsByPort[f.Key.LocalPort]
						    }
						    if ok {
							    if info, ok := inodes[inode]; ok {
								    f.PID = info.PID
								    f.Comm = info.Comm
							    }
						    }
					    }

					    if f.Hostname == "" {
						    f.Hostname = ft.resolver.Lookup(f.Key.RemoteIP)
					    }
				    }
			    }

			    func (ft *FlowTable) Snapshot() []FlowStats {
				    ft.mu.Lock()
				    defer ft.mu.Unlock()

				    out := make([]FlowStats, 0, len(ft.flows))
				    for _, f := range ft.flows {
					    out = append(out, *f)
				    }
				    sort.Slice(out, func(i, j int) bool {
					    return out[i].LastSeen.After(out[j].LastSeen)
				    })
				    return out
			    }

			    // Aggregate группирует потоки по SNI/hostname/IP и возвращает суммарную статистику.
			    func (ft *FlowTable) Aggregate() []AggregatedFlow {
				    flows := ft.Snapshot()

				    groups := make(map[string]*AggregatedFlow)

				    for i := range flows {
					    f := &flows[i]

					    // Пропускаем LAN-трафик (к локальным адресам) — это не интересно для аудита
					    if isLANIP(f.Key.RemoteIP) {
						    continue
					    }

					    label := f.SNI
					    if label == "" && f.Hostname != "" {
						    if !strings.HasSuffix(f.Hostname, ".1e100.net") {
							    label = f.Hostname
						    }
					    }
					    if label == "" {
						    label = f.Key.RemoteIP
					    }

					    process := "?"
					    if f.Comm != "" {
						    process = fmt.Sprintf("%s(%d)", f.Comm, f.PID)
					    } else if mac, ok := ft.arpTable[f.Key.LocalIP]; ok {
						    process = fmt.Sprintf("%s (%s)", f.Key.LocalIP, proc.DescribeMAC(mac))
					    } else {
						    process = f.Key.LocalIP
					    }

					    // Добавляем флаг к label
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

					    g.Connections++
					    g.PacketsOut += f.PacketsOut
					    g.BytesOut += f.BytesOut
					    g.PacketsIn += f.PacketsIn
					    g.BytesIn += f.BytesIn
					    g.Retransmits += f.Retransmits
					    g.Gaps += f.Gaps

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
				    }

				    out := make([]AggregatedFlow, 0, len(groups))
				    for _, g := range groups {
					    out = append(out, *g)
				    }
				    sort.Slice(out, func(i, j int) bool {
					    return out[i].LastSeen.After(out[j].LastSeen)
				    })
				    return out
			    }

			    // isNoisy определяет keep-alive-подобные потоки.
			    func isNoisy(f *FlowStats) bool {
				    totalPkts := f.PacketsOut + f.PacketsIn
				    if totalPkts == 0 {
					    return true
				    }
				    totalBytes := f.BytesOut + f.BytesIn
				    avgSize := float64(totalBytes) / float64(totalPkts)

				    age := time.Since(f.FirstSeen).Seconds()
				    if age <= 0 {
					    age = 1
				    }
				    pktPerSec := float64(totalPkts) / age

				    // Классический keep-alive: медленно и маленькие пакеты
				    if pktPerSec < 1.0 && avgSize < 100 {
					    return true
				    }
				    // Затихший поток: активность > 10 сек назад, объём < 10 KB
				    if time.Since(f.LastSeen) > 10*time.Second && totalBytes < 10*1024 {
					    return true
				    }
				    return false
			    }

			    func (ft *FlowTable) Print() {
				    ft.mu.Lock()
				    minPkts := ft.minPkts
				    hideIdle := ft.hideIdle
				    activeOnly := ft.activeOnly
				    ft.mu.Unlock()

				    allGroups := ft.Aggregate()

				    groups := make([]AggregatedFlow, 0, len(allGroups))
				    hiddenByPkts := 0
				    hiddenByIdle := 0
				    hiddenByNoise := 0
				    hiddenByActive := 0
				    now := time.Now()

				    for _, g := range allGroups {
					    totalPkts := g.PacketsOut + g.PacketsIn

					    if minPkts > 0 && totalPkts < uint64(minPkts) {
						    hiddenByPkts++
						    continue
					    }
					    if hideIdle && now.Sub(g.LastSeen) > 30*time.Second {
						    hiddenByIdle++
						    continue
					    }
					    if activeOnly > 0 && now.Sub(g.LastSeen) > time.Duration(activeOnly)*time.Second {
						    hiddenByActive++
						    continue
					    }
					    // isNoisy проверяем по агрегату: медленно и мелко
					    totalBytes := g.BytesOut + g.BytesIn
					    ageSec := time.Since(g.FirstSeen).Seconds()
					    if ageSec <= 0 {
						    ageSec = 1
					    }
					    pktPerSec := float64(totalPkts) / ageSec
					    var avgSize float64
					    if totalPkts > 0 {
						    avgSize = float64(totalBytes) / float64(totalPkts)
					    }
					    if pktPerSec < 1.0 && avgSize < 100 {
						    hiddenByNoise++
						    continue
					    }
					    if now.Sub(g.LastSeen) > 10*time.Second && totalBytes < 10*1024 {
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
				    hidden := hiddenByPkts + hiddenByIdle + hiddenByActive + hiddenByNoise
				    if hidden > 0 {
					    fmt.Printf(", скрыто: %d pkts / %d idle / %d active / %d шум",
						       hiddenByPkts, hiddenByIdle, hiddenByActive, hiddenByNoise)
				    }
				    fmt.Printf(") ===\n")

				    fmt.Printf("%-28s %-32s %-5s %5s %8s %8s %10s %10s %4s %4s %5s\n",
					       "PROCESS", "SNI / REMOTE", "PROTO", "CONNS", "PKT/S", "AVG_SZ", "OUT", "IN", "RETR", "GAPS", "AGE")

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

					    process := g.Process
					    label := truncate(g.Label, 32)

					    fmt.Printf("%-28s %-32s %-5s %5d %8.1f %8.0f %10s %10s %4d %4d %5s\n",
						       truncate(process, 28),
						       label,
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

			    func truncate(s string, n int) string {
				    if len(s) <= n {
					    return s
				    }
				    if n <= 1 {
					    return s[:n]
				    }
				    return s[:n-1] + "…"
			    }

			    type TCPFlags struct {
				    SYN, ACK, FIN, RST, PSH bool

				    MSS           uint16
				    WindowScale   uint8
				    HasTimestamps bool
				    HasSACK       bool

				    Payload []byte
			    }

			    // PrintProfile печатает тайминг-профиль для указанного SNI.
			    // Если matchSNI пуст — ничего не делает.
			    func (ft *FlowTable) PrintProfile(matchSNI string) {
				    if matchSNI == "" {
					    return
				    }

				    flows := ft.Snapshot()

				    // Собираем все потоки с этим SNI
				    var matched []FlowStats
				    for _, f := range flows {
					    if f.SNI == matchSNI {
						    matched = append(matched, f)
					    }
				    }
				    if len(matched) == 0 {
					    fmt.Printf("\n=== Профиль для %q: потоков не найдено ===\n", matchSNI)
					    return
				    }

				    // Суммируем метрики по всем потокам с этим SNI
				    var (
					    intervalBuckets [6]uint64
					    sizeBuckets     [7]uint64
					    timeline        [60]uint64
					    totalBytesOut   uint64
					    totalBytesIn    uint64
					    totalPkts       uint64
				    )

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

					    for i := 0; i < 60; i++ {
						    timeline[i] += f.Timeline[i]
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

				    // Интервалы
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

				    // Timeline
				    fmt.Println()
				    fmt.Println("  ── Timeline (последние 60 сек, слева = старая) ──")
				    now := time.Now().Unix()
				    maxVal := uint64(0)
				    for i := 0; i < 60; i++ {
					    if timeline[i] > maxVal {
						    maxVal = timeline[i]
					    }
				    }
				    if maxVal == 0 {
					    fmt.Println("  (нет данных)")
				    } else {
					    // Печатаем bar-график: 60 символов, по одному на секунду
					    fmt.Print("  ")
					    for i := 0; i < 60; i++ {
						    sec := (now - 59 + int64(i)) % 60
						    val := timeline[sec]
						    if val == 0 {
							    fmt.Print(" ")
						    } else {
							    // 5 уровней интенсивности
							    ratio := float64(val) / float64(maxVal)
							    switch {
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
				    barLen := int(pct / 2) // 50 символов максимум
				    if barLen > 50 {
					    barLen = 50
				    }
				    bar := ""
				    for i := 0; i < barLen; i++ {
					    bar += "█"
				    }
				    fmt.Printf("%s %8d  %5.1f%%  %s\n", label, count, pct, bar)
			    }
