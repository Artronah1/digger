package capture

import (
	"fmt"
	"sort"
	"time"
)

// Attribution — связка одного TCP-потока с DNS-именами.
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

// ProxyReason возвращает причину, по которой поток похож на прокси.
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
	Reason     string
	Age        time.Duration
}

// BuildAttributions строит таблицу связок для потоков с SNI или remote IP.
func BuildAttributions(flows []FlowStats, mapping *DNSMapping) []Attribution {
	var out []Attribution
	now := time.Now()

	for _, f := range flows {
		if f.Key.RemoteIP == "" {
			continue
		}
		if f.Key.Proto != "TCP" {
			continue
		}
		if isPrivateIP(f.Key.RemoteIP) {
			continue
		}

		a := Attribution{
			LocalIP:    f.Key.LocalIP,
			LocalPort:  f.Key.LocalPort,
			RemoteIP:   f.Key.RemoteIP,
			RemotePort: f.Key.RemotePort,
			SNI:        f.SNI,
			FirstSeen:  f.FirstSeen,
			Age:        now.Sub(f.FirstSeen),
		}

		a.DNSNames = mapping.NamesForIP(f.Key.RemoteIP)

		if f.SNI != "" {
			for _, name := range a.DNSNames {
				if name == f.SNI {
					a.Matched = true
					break
				}
			}
			if !a.Matched && len(a.DNSNames) > 0 {
				a.Mismatch = true
			}
		}

		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].FirstSeen.After(out[j].FirstSeen)
	})
	return out
}

// BuildProxySuspicions собирает потоки, похожие на прокси-трафик.
func BuildProxySuspicions(flows []FlowStats, mapping *DNSMapping) []ProxySuspicion {
	now := time.Now()
	var out []ProxySuspicion

	for _, f := range flows {
		if f.Key.RemoteIP == "" || f.Key.Proto != "TCP" {
			continue
		}
		if isPrivateIP(f.Key.RemoteIP) {
			continue
		}

		proc := f.Comm

		var reason string

		if f.SNI != "" {
			res := resolveSNIAt(f.SNI, f.Key.RemoteIP, f.LastSeen, mapping)
			if !res.Matches {
				switch res.Reason {
				case "not-resolved":
					// Домен вообще не резолвится — сильный признак прокси-фронта
					reason = "SNI не резолвится — прокси-фронт?"
				case "no-observation":
					// Наблюдений нет, но и резолва нет
					reason = "SNI без DNS-наблюдения — возможно прокси?"
				case "no-mapping":
					// Маппинг пуст — не можем проверить
					reason = ""
				case "different-ip":
					// Резолвится в другой IP — CDN-балансировка, не прокси
					reason = ""
				}
			}
		}

		// Процесс — известный прокси-клиент, SNI нет, IP не российский.
		if reason == "" && looksLikeProxyProcess(proc) && f.SNI == "" {
			if !isLikelyRussianIP(f.Key.RemoteIP) {
				reason = "процесс-прокси на не-российский IP"
			}
		}

		if reason == "" {
			continue
		}

		out = append(out, ProxySuspicion{
			LocalIP:    f.Key.LocalIP,
			LocalPort:  f.Key.LocalPort,
			RemoteIP:   f.Key.RemoteIP,
			RemotePort: f.Key.RemotePort,
			SNI:        f.SNI,
			Process:    proc,
			Reason:     reason,
			Age:        now.Sub(f.FirstSeen),
		})
	}

	// Дедуп
	seen := make(map[string]bool)
	deduped := out[:0]
	for _, s := range out {
		key := s.SNI + "|" + s.RemoteIP + "|" + s.Process
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, s)
	}
	return deduped
}

// printAttribution выводит таблицу связок DNS ↔ SNI ↔ IP.
func printAttribution(flows []FlowStats, mapping *DNSMapping) {
	attrs := BuildAttributions(flows, mapping)
	if len(attrs) == 0 {
		return
	}

	matched := 0
	mismatched := 0
	unresolved := 0
	for _, a := range attrs {
		switch {
		case a.Matched:
			matched++
		case a.Mismatch:
			mismatched++
		case len(a.DNSNames) == 0 && a.SNI == "":
			unresolved++
		}
	}

	fmt.Printf("\n=== Связки DNS ↔ SNI ↔ IP (%d) ===\n", len(attrs))
	if mismatched > 0 {
		fmt.Printf("⚠  несовпадений SNI ↔ DNS: %d\n", mismatched)
	}
	fmt.Printf("✓ совпало: %d   ⚠ не совпало: %d   ? без DNS: %d\n\n",
		matched, mismatched, unresolved)

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
		if a.Matched {
			status = "✓"
		} else if a.Mismatch {
			status = "⚠"
		} else if len(a.DNSNames) > 0 {
			status = "~"
		} else if a.SNI != "" {
			status = "✗"
		}

		fmt.Printf("%-22s %-16s %-32s %-32s %-6s %s\n",
			truncate(local, 22),
			a.RemoteIP,
			truncate(sni, 32),
			truncate(dnsNames, 32),
			status,
			a.Age.Truncate(time.Second).String())
	}
	fmt.Println()
}

// printProxySuspicions выводит потоки, похожие на прокси/VPN-клиент.
func printProxySuspicions(flows []FlowStats, mapping *DNSMapping, anomaly *AnomalyDetector) {
	sus := BuildProxySuspicions(flows, mapping)
	if len(sus) == 0 {
		return
	}

	// Регистрируем в детекторе аномалий
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

// BuildProxyProcesses собирает агрегат по процессам-прокси.
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
		if f.Comm == "" {
			continue
		}
		if !looksLikeProxyProcess(f.Comm) {
			continue
		}
		if isPrivateIP(f.Key.RemoteIP) {
			continue
		}

		g, ok := groups[f.Comm]
		if !ok {
			g = &agg{
				remoteIPs: make(map[string]bool),
				firstSeen: f.FirstSeen,
			}
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

	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
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
