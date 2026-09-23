package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AnomalyDetector отслеживает подозрительные паттерны.
type AnomalyDetector struct {
	mu            sync.Mutex
	knownDomains  map[string]bool
	historyPath   string
	historyDirty  bool

	// Кэш для дедупликации вывода
	reportedNew   map[string]time.Time
	reportedHash  map[string]time.Time
	reportedLeak  map[string]time.Time
}

// regex для хеш-подобного левого label
var hashLabelRe = regexp.MustCompile(`^[a-f0-9]{16,}$|^[A-Za-z0-9_-]{20,}$`)

func NewAnomalyDetector() *AnomalyDetector {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".digger")
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "known_domains.txt")

	ad := &AnomalyDetector{
		knownDomains: make(map[string]bool),
		historyPath:  path,
		reportedNew:  make(map[string]time.Time),
		reportedHash: make(map[string]time.Time),
		reportedLeak: make(map[string]time.Time),
	}
	ad.loadHistory()
	return ad
}

func (ad *AnomalyDetector) loadHistory() {
	data, err := os.ReadFile(ad.historyPath)
	if err != nil {
		return // файла нет — первый запуск
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ad.knownDomains[line] = true
		}
	}
}

// SaveHistory сохраняет обновлённую историю на диск.
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

// CheckDomain проверяет домен и возвращает метку аномалии (или "").
func (ad *AnomalyDetector) CheckDomain(domain string, isDNS bool) string {
	if domain == "" {
		return ""
	}

	// Пропускаем PTR-запросы — это обратный DNS, инициируемый самим digger'ом
	if strings.HasSuffix(domain, ".in-addr.arpa") ||
		strings.HasSuffix(domain, ".ip6.arpa") {
			return ""
		}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	var flags []string

	// 1. Хеш-подобный поддомен
	labels := strings.Split(domain, ".")
	if len(labels) > 1 {
		leftLabel := labels[0]
		if hashLabelRe.MatchString(leftLabel) {
			if _, reported := ad.reportedHash[domain]; !reported ||
				now.Sub(ad.reportedHash[domain]) > 5*time.Minute {
					flags = append(flags, "⚠HASH")
					ad.reportedHash[domain] = now
				}
		}
	}

	// 2. Новый домен (только для DNS-запросов, чтобы не шуметь на SNI)
	if isDNS {
		if !ad.knownDomains[domain] {
			if _, reported := ad.reportedNew[domain]; !reported ||
				now.Sub(ad.reportedNew[domain]) > 5*time.Minute {
					flags = append(flags, "⚡NEW")
					ad.reportedNew[domain] = now
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

// CheckDNSLeak проверяет, идёт ли DNS-запрос к локальному резолверу.
// Возвращает "" если всё ок, иначе метку.
func (ad *AnomalyDetector) CheckDNSLeak(dstIP string) string {
	if isLANIP(dstIP) {
		return ""
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	key := dstIP
	if _, reported := ad.reportedLeak[key]; reported &&
		now.Sub(ad.reportedLeak[key]) < 5*time.Minute {
			return ""
		}
		ad.reportedLeak[key] = now
		return fmt.Sprintf("⚠DNS-LEAK → %s", dstIP)
}
