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
	DNSNames   []string // имена, которые резолвились в RemoteIP
	Matched    bool     // SNI совпадает с одним из DNSNames
	Mismatch   bool     // SNI есть, но DNS его не подтверждает
	FirstSeen  time.Time
	Age        time.Duration
}

// BuildAttributions строит таблицу связок для потоков с SNI или remote IP.
func BuildAttributions(flows []FlowStats, mapping *DNSMapping) []Attribution {
	var out []Attribution

	now := time.Now()

	for _, f := range flows {
		// Пропускаем потоки без смысла
		if f.Key.RemoteIP == "" {
			continue
		}
		if f.Key.Proto != "TCP" {
			continue
		}
		// Пропускаем локальные адреса
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

		// Имена, которые резолвились в этот IP
		a.DNSNames = mapping.NamesForIP(f.Key.RemoteIP)

		// Проверяем совпадение
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

// printAttribution выводит таблицу связок DNS ↔ SNI ↔ IP.
func printAttribution(flows []FlowStats, mapping *DNSMapping) {
	attrs := BuildAttributions(flows, mapping)
	if len(attrs) == 0 {
		return
	}

	// Считаем статистику
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
			// Показываем первое имя
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
			status = "~" // DNS есть, но SNI пуст → атрибуция по IP
		} else if a.SNI != "" {
			status = "✗" // SNI есть, DNS нет
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
