package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// AnomalyDetector отслеживает подозрительные паттерны.
type AnomalyDetector struct {
	mu           sync.Mutex
	knownDomains map[string]bool
	historyPath  string
	historyDirty bool

	reportedNew  map[string]time.Time
	reportedHash map[string]time.Time
	reportedLeak map[string]time.Time

	anomalies []AnomalyRecord

	printed map[string]bool

	dnsOnlyDomains map[string]time.Time
	dnsOnlyCounts  map[string]int
}

// AnomalyRecord — одна запись об аномалии.
type AnomalyRecord struct {
	Time    time.Time
	Kind    string
	Domain  string
	Detail  string
	Process string
	SrcIP   string
}

var hashLabelRe = regexp.MustCompile(`^[a-f0-9]{16,}$|^[A-Za-z0-9_-]{20,}$`)

func NewAnomalyDetector() *AnomalyDetector {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".digger")
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "known_domains.txt")

	ad := &AnomalyDetector{
		knownDomains:   make(map[string]bool),
		historyPath:    path,
		reportedNew:    make(map[string]time.Time),
		reportedHash:   make(map[string]time.Time),
		reportedLeak:   make(map[string]time.Time),
		printed:        make(map[string]bool),
		dnsOnlyDomains: make(map[string]time.Time),
		dnsOnlyCounts:  make(map[string]int),
	}
	ad.loadHistory()
	return ad
}

func (ad *AnomalyDetector) loadHistory() {
	data, err := os.ReadFile(ad.historyPath)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ad.knownDomains[line] = true
		}
	}
}

func (ad *AnomalyDetector) SaveHistory() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if !ad.historyDirty {
		return
	}
	var sb strings.Builder
	for d := range ad.knownDomains {
		sb.WriteString(d)
		sb.WriteByte('\n')
	}
	os.WriteFile(ad.historyPath, []byte(sb.String()), 0644)
}

func (ad *AnomalyDetector) CheckDomain(domain string, isDNS bool) string {
	if domain == "" {
		return ""
	}

	if strings.HasSuffix(domain, ".in-addr.arpa") ||
		strings.HasSuffix(domain, ".ip6.arpa") {
			return ""
		}

		ad.mu.Lock()
		defer ad.mu.Unlock()

		now := time.Now()
		var flags []string

		labels := strings.Split(domain, ".")
		if len(labels) > 1 {
			leftLabel := labels[0]
			if hashLabelRe.MatchString(leftLabel) {
				if _, reported := ad.reportedHash[domain]; !reported ||
					now.Sub(ad.reportedHash[domain]) > 5*time.Minute {
						flags = append(flags, "⚠HASH")
						ad.reportedHash[domain] = now
						ad.anomalies = append(ad.anomalies, AnomalyRecord{
							Time:   now,
							Kind:   "HASH",
							Domain: domain,
						})
					}
			}
		}

		if isDNS {
			if !ad.knownDomains[domain] {
				if _, reported := ad.reportedNew[domain]; !reported ||
					now.Sub(ad.reportedNew[domain]) > 5*time.Minute {
						flags = append(flags, "⚡NEW")
						ad.reportedNew[domain] = now
						ad.anomalies = append(ad.anomalies, AnomalyRecord{
							Time:   now,
							Kind:   "NEW",
							Domain: domain,
						})
					}
					ad.knownDomains[domain] = true
					ad.historyDirty = true
			}
		}

		if len(flags) == 0 {
			return ""
		}
		return strings.Join(flags, " ")
}

func (ad *AnomalyDetector) CheckDNSLeak(dstIP, domain string) string {
	if isLANIP(dstIP) {
		return ""
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	if _, reported := ad.reportedLeak[dstIP]; reported &&
		now.Sub(ad.reportedLeak[dstIP]) < 5*time.Minute {
			return ""
		}
		ad.reportedLeak[dstIP] = now

		ad.anomalies = append(ad.anomalies, AnomalyRecord{
			Time:   now,
			Kind:   "DNS-LEAK",
			Domain: domain,
			Detail: fmt.Sprintf("→ %s", dstIP),
		})

		return fmt.Sprintf("⚠DNS-LEAK → %s", dstIP)
}

// RecordDNSOnly запоминает DNS-запрос без последующего соединения.
func (ad *AnomalyDetector) RecordDNSOnly(domain string) {
	if domain == "" {
		return
	}
	if strings.HasSuffix(domain, ".in-addr.arpa") ||
		strings.HasSuffix(domain, ".ip6.arpa") {
			return
		}

		ad.mu.Lock()
		defer ad.mu.Unlock()

		// Если домен уже был в истории — не считаем beaconing
		if ad.knownDomains[domain] {
			return
		}

		now := time.Now()
		if _, ok := ad.dnsOnlyDomains[domain]; !ok {
			ad.dnsOnlyDomains[domain] = now
		}
		ad.dnsOnlyCounts[domain]++

		count := ad.dnsOnlyCounts[domain]
		first := ad.dnsOnlyDomains[domain]
		elapsed := now.Sub(first)

		if count >= 3 && elapsed >= 30*time.Second {
			key := "BEACON|" + domain
			if ad.printed[key] {
				return
			}
			ad.printed[key] = true

			ad.anomalies = append(ad.anomalies, AnomalyRecord{
				Time:   now,
				Kind:   "BEACON",
				Domain: domain,
				Detail: fmt.Sprintf("(%d DNS за %s без соединений)", count, elapsed.Truncate(time.Second)),
			})
		}
}

// MarkConnected — если домен соединился, сбрасываем счётчик beaconing.
func (ad *AnomalyDetector) MarkConnected(domain string) {
	if domain == "" {
		return
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	delete(ad.dnsOnlyDomains, domain)
	delete(ad.dnsOnlyCounts, domain)
}

func (ad *AnomalyDetector) SetProcessForDomain(domain, process string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	for i := len(ad.anomalies) - 1; i >= 0; i-- {
		if ad.anomalies[i].Domain == domain && ad.anomalies[i].Process == "" {
			ad.anomalies[i].Process = process
			return
		}
	}
}

func (ad *AnomalyDetector) CollectAnomalies(window time.Duration) []AnomalyRecord {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	cutoff := time.Now().Add(-window)
	out := make([]AnomalyRecord, 0)
	for _, a := range ad.anomalies {
		if a.Time.After(cutoff) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}

func (ad *AnomalyDetector) PrintAnomalies(window time.Duration) {
	records := ad.CollectAnomalies(window)
	if len(records) == 0 {
		return
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	newRecords := make([]AnomalyRecord, 0)
	for _, a := range records {
		key := a.Kind + "|" + a.Domain + "|" + a.Detail
		if ad.printed[key] {
			continue
		}
		ad.printed[key] = true
		newRecords = append(newRecords, a)
	}

	if len(newRecords) == 0 {
		return
	}

	fmt.Printf("\n=== ⚠ Подозрительное (новое) ===\n")
	for _, a := range newRecords {
		ts := a.Time.Format("15:04:05")

		kind := ""
		switch a.Kind {
			case "NEW":
				kind = "⚡NEW "
			case "HASH":
				kind = "⚠HASH"
			case "DNS-LEAK":
				kind = "⚠LEAK"
			case "BEACON":
				kind = "⚠BEACON"
			default:
				kind = a.Kind
		}

		proc := a.Process
		if proc == "" {
			proc = "?"
		}

		detail := ""
		if a.Detail != "" {
			detail = " " + a.Detail
		}

		fmt.Printf("[%s] %-8s %-40s %s%s\n",
			   ts, kind, truncate(a.Domain, 40), proc, detail)
	}
	fmt.Println()
}
