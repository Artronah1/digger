package capture

import (
	"fmt"
	"slices"
	"sort"
	"time"
)

// --- Типы ---

// Attribution — связка одного TCP-потока с DNS-именами: SNI ↔ DNS ↔ IP.
type Attribution struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	SNI        string
	DNSNames   []string
	Matched    bool
	Mismatch   bool
	FirstSeen  time.Time
	Age        time.Duration
}

// ProxyReason возвращает причину, по которой связка похожа на прокси.
// NOTE: в BuildProxySuspicions используется своя логика (resolveSNIAt),
// и вывод по mismatch ей противоречит. Проверить, задействован ли метод
// (JSON-вывод?) — иначе удалить.
func (a *Attribution) ProxyReason() string {
	if a.SNI != "" && len(a.DNSNames) == 0 {
		return "SNI без DNS — reality/trojan/vless?"
	}
	if a.SNI != "" && a.Mismatch {
		return "SNI ≠ DNS — подмена/прикрытие"
	}
	return ""
}

// ProxySuspicion — поток, похожий на прокси-трафик.
type ProxySuspicion struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	SNI        string
	Process    string
	Reason     string // человекочитаемая причина
	ReasonCode string // машинный код: sni-not-resolved | sni-no-observation | process
	Age        time.Duration
}

// ProxyProcess — агрегат по процессу-прокси.
type ProxyProcess struct {
	Process   string
	Conns     int
	BytesOut  uint64
	BytesIn   uint64
	RemoteIPs int
	FirstSeen time.Time
	LastSeen  time.Time
}

// --- Общие фильтры ---

// isPublicTCPFlow: TCP-поток на публичный IP — кандидат на атрибуцию.
func isPublicTCPFlow(f FlowStats) bool {
	return f.Key.RemoteIP != "" &&
		f.Key.Proto == protoTCP &&
		!isPrivateIP(f.Key.RemoteIP)
}

// --- Builders ---

// BuildAttributions строит таблицу связок для публичных TCP-потоков.
func BuildAttributions(flows []FlowStats, mapping *DNSMapping) []Attribution {
	out := make([]Attribution, 0, len(flows))
	now := time.Now()

	for _, f := range flows {
		if !isPublicTCPFlow(f) {
			continue
		}

		dnsNames := mapping.NamesForIP(f.Key.RemoteIP)

		a := Attribution{
			LocalIP:    f.Key.LocalIP,
			LocalPort:  f.Key.LocalPort,
			RemoteIP:   f.Key.RemoteIP,
			RemotePort: f.Key.RemotePort,
			SNI:        f.SNI,
			DNSNames:   dnsNames,
			FirstSeen:  f.FirstSeen,
			Age:        now.Sub(f.FirstSeen),
		}

		// Сравниваем SNI с DNS-именами этого IP (если есть и то и другое).
		if f.SNI != "" && len(dnsNames) > 0 {
			a.Matched = slices.Contains(dnsNames, f.SNI)
			a.Mismatch = !a.Matched
		}

		out = append(out, a)
	}

	// Новые сверху.
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.After(out[j].FirstSeen) })
	return out
}

// BuildProxySuspicions собирает потоки, похожие на прокси-трафик.
func BuildProxySuspicions(flows []FlowStats, mapping *DNSMapping) []ProxySuspicion {
	now := time.Now()
	var out []ProxySuspicion

	for _, f := range flows {
		if !isPublicTCPFlow(f) {
			continue
		}

		code, reason := sniProxyReason(f, mapping)
		if code == "" {
			code, reason = proxyProcessReason(f)
		}
		if code == "" {
			continue
		}

		out = append(out, ProxySuspicion{
			LocalIP:    f.Key.LocalIP,
			LocalPort:  f.Key.LocalPort,
			RemoteIP:   f.Key.RemoteIP,
			RemotePort: f.Key.RemotePort,
			SNI:        f.SNI,
			Process:    f.Comm,
			Reason:     reason,
			ReasonCode: code,
			Age:        now.Sub(f.FirstSeen),
		})
	}

	// Новые сверху — стабильный порядок вывода между циклами печати.
	sort.Slice(out, func(i, j int) bool { return out[i].Age < out[j].Age })

	// Дедуп по (устройство, SNI, IP, процесс). Запись идёт поверх
	// исходного слайса: индекс записи всегда <= индекса чтения.
	seen := make(map[string]bool, len(out))
	deduped := out[:0]
	for _, s := range out {
		key := s.LocalIP + "|" + s.SNI + "|" + s.RemoteIP + "|" + s.Process
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, s)
	}
	return deduped
}

// sniProxyReason — причина «похоже на прокси» по SNI; ("", "") — не похоже.
func sniProxyReason(f FlowStats, mapping *DNSMapping) (code, text string) {
	if f.SNI == "" {
		return "", ""
	}

	res := resolveSNIAt(f.SNI, f.Key.RemoteIP, f.LastSeen, mapping)
	if res.Matches {
		return "", ""
	}
	switch res.Reason {
	case "not-resolved":
		// Домен вообще не резолвится — сильный признак прокси-фронта.
		return "sni-not-resolved", "SNI не резолвится — прокси-фронт?"
	case "no-observation":
		// Резолва нет и наблюдений нет.
		return "sni-no-observation", "SNI без DNS-наблюдения — возможно прокси?"
	default:
		// "no-mapping" — нечем проверить;
		// "different-ip" — CDN-балансировка, не прокси.
		return "", ""
	}
}

// proxyProcessReason — известный прокси-клиент без SNI на не-российский IP.
func proxyProcessReason(f FlowStats) (code, text string) {
	if f.SNI != "" || !looksLikeProxyProcess(f.Comm) {
		return "", ""
	}
	switch geoipCountry(f.Key.RemoteIP) {
	case "", "RU": // нет GeoIP-базы или Россия — не флажим
		return "", ""
	}
	return "process", "процесс-прокси на не-российский IP"
}

// BuildProxyProcesses собирает агрегат по процессам-прокси:
// все публичные потоки процессов, похожих на прокси-клиентов.
func BuildProxyProcesses(flows []FlowStats) []ProxyProcess {
	type agg struct {
		conns     int
		bytesOut  uint64
		bytesIn   uint64
		remoteIPs map[string]bool
		firstSeen time.Time
		lastSeen  time.Time
	}

	groups := make(map[string]*agg)

	for _, f := range flows {
		if f.Comm == "" || !looksLikeProxyProcess(f.Comm) {
			continue
		}
		if isPrivateIP(f.Key.RemoteIP) {
			continue
		}

		g, ok := groups[f.Comm]
		if !ok {
			g = &agg{remoteIPs: make(map[string]bool), firstSeen: f.FirstSeen}
			groups[f.Comm] = g
		}
		g.conns++
		g.bytesOut += f.BytesOut
		g.bytesIn += f.BytesIn
		g.remoteIPs[f.Key.RemoteIP] = true
		if f.LastSeen.After(g.lastSeen) {
			g.lastSeen = f.LastSeen
		}
		if f.FirstSeen.Before(g.firstSeen) {
			g.firstSeen = f.FirstSeen
		}
	}

	out := make([]ProxyProcess, 0, len(groups))
	for name, g := range groups {
		out = append(out, ProxyProcess{
			Process:   name,
			Conns:     g.conns,
			BytesOut:  g.bytesOut,
			BytesIn:   g.bytesIn,
			RemoteIPs: len(g.remoteIPs),
			FirstSeen: g.firstSeen,
			LastSeen:  g.lastSeen,
		})
	}

	// Недавно активные сверху.
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// --- Вывод ---

// printAttribution выводит таблицу связок DNS ↔ SNI ↔ IP.
//
// Статусы: ✓ SNI совпал с DNS · ⚠ SNI ≠ DNS · ~ DNS есть, SNI нет ·
// ✗ SNI есть, DNS нет · ? ни того, ни другого.
func printAttribution(flows []FlowStats, mapping *DNSMapping) {
	attrs := BuildAttributions(flows, mapping)
	if len(attrs) == 0 {
		return
	}

	var matched, mismatched, sniNoDNS, plain int
	for _, a := range attrs {
		switch {
		case a.Matched:
			matched++
		case a.Mismatch:
			mismatched++
		case len(a.DNSNames) > 0:
			// "~": атрибуция по DNS, SNI нет.
		case a.SNI != "":
			sniNoDNS++ // ✗ — SNI без DNS, классический признак прокси
		default:
			plain++ // "?"
		}
	}

	fmt.Printf("\n=== Связки DNS ↔ SNI ↔ IP (%d) ===\n", len(attrs))
	if mismatched > 0 {
		fmt.Printf("⚠  несовпадений SNI ↔ DNS: %d\n", mismatched)
	}
	fmt.Printf("✓ совпало: %d   ⚠ не совпало: %d   ✗ SNI без DNS: %d   ? без атрибуции: %d\n\n",
		matched, mismatched, sniNoDNS, plain)

	fmt.Printf("%-22s %-16s %-32s %-32s %-6s %s\n",
		"LOCAL", "REMOTE IP", "SNI", "DNS (names для этого IP)", "STATUS", "AGE")

	for _, a := range attrs {
		local := fmt.Sprintf("%s:%d", a.LocalIP, a.LocalPort)
		sni := a.SNI
		if sni == "" {
			sni = "—"
		}

		dnsNames := "—"
		if len(a.DNSNames) > 0 {
			dnsNames = a.DNSNames[0]
			if len(a.DNSNames) > 1 {
				dnsNames += fmt.Sprintf(" (+%d)", len(a.DNSNames)-1)
			}
		}

		status := "?"
		switch {
		case a.Matched:
			status = "✓"
		case a.Mismatch:
			status = "⚠"
		case len(a.DNSNames) > 0:
			status = "~"
		case a.SNI != "":
			status = "✗"
		}

		fmt.Printf("%-22s %-16s %-32s %-32s %-6s %s\n",
			truncate(local, 22),
			truncate(a.RemoteIP, 16),
			truncate(sni, 32),
			truncate(dnsNames, 32),
			status,
			a.Age.Truncate(time.Second).String())
	}
	fmt.Println()
}

// printProxySuspicions выводит потоки, похожие на прокси/VPN-клиент,
// и регистрирует их в детекторе аномалий (дедуп внутри RecordProxy).
func printProxySuspicions(flows []FlowStats, mapping *DNSMapping, anomaly *AnomalyDetector) {
	sus := BuildProxySuspicions(flows, mapping)
	if len(sus) == 0 {
		return
	}

	if anomaly != nil {
		for _, s := range sus {
			anomaly.RecordProxy(s.SNI, s.RemoteIP, s.Process, s.Reason)
		}
	}

	fmt.Printf("\n=== ⚠ Похоже на прокси/VPN-клиент (%d) ===\n", len(sus))
	fmt.Printf("%-16s %-22s %-32s %-22s %-6s %s\n",
		"LOCAL", "REMOTE", "SNI", "PROCESS", "AGE", "ПРИЧИНА")

	for _, s := range sus {
		local := fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
		remote := fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort)
		sni := s.SNI
		if sni == "" {
			sni = "—"
		}
		proc := s.Process
		if proc == "" {
			proc = "?"
		}

		fmt.Printf("%-16s %-22s %-32s %-22s %-6s %s\n",
			truncate(local, 16),
			truncate(remote, 22),
			truncate(sni, 32),
			truncate(proc, 22),
			s.Age.Truncate(time.Second).String(),
			s.Reason)
	}
	fmt.Println()
}

// printProxyProcesses выводит таблицу процессов-прокси.
func printProxyProcesses(flows []FlowStats) {
	procs := BuildProxyProcesses(flows)
	if len(procs) == 0 {
		return
	}

	fmt.Printf("\n=== ⚠ Прокси-процессы (%d) ===\n", len(procs))
	fmt.Printf("%-22s %6s %10s %10s %6s %6s\n",
		"PROCESS", "CONNS", "OUT", "IN", "IPs", "AGE")

	for _, p := range procs {
		age := time.Since(p.FirstSeen).Truncate(time.Second)
		fmt.Printf("%-22s %6d %10s %10s %6d %6s\n",
			truncate(p.Process, 22),
			p.Conns,
			humanBytes(p.BytesOut),
			humanBytes(p.BytesIn),
			p.RemoteIPs,
			age.String())
	}
	fmt.Println()
}
