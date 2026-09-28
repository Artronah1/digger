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
		dnsNames := mapping.NamesForIP(f.Key.RemoteIP)

		var reason string

		if f.SNI != "" {
			if len(dnsNames) == 0 {
				// DNS не захвачен — резолвим сами.
				if !sniResolvesToIP(f.SNI, f.Key.RemoteIP) {
					reason = "SNI не резолвится в этот IP — прокси?"
				}
			} else {
				matched := false
				for _, n := range dnsNames {
					if n == f.SNI {
						matched = true
						break
					}
				}
				if !matched {
					reason = "SNI ≠ DNS — подмена/прикрытие"
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
func printProxySuspicions(flows []FlowStats, mapping *DNSMapping) {
	sus := BuildProxySuspicions(flows, mapping)
	if len(sus) == 0 {
		return
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
