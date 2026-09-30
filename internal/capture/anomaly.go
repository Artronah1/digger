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

// --- Константы (были магическими числами) ---

const (
	dedupWindow   = 5 * time.Minute // не повторять отчёт по тому же ключу
	recordMaxAge  = 1 * time.Hour   // срок жизни записей и состояния (>= окон отчётов)
	sweepInterval = 5 * time.Minute // период уборки устаревшего состояния

	beaconMinCount   = 3                // DNS-запросов...
	beaconMinElapsed = 30 * time.Second // ...за это время без соединений
)

// hashLabelRe — левая метка, похожая на хеш/токен: hex ≥16 или
// любая последовательность ≥20. Широкий паттерн — даёт ложные
// срабатывания на длинных именах CDN; при желании ужесточить.
var hashLabelRe = regexp.MustCompile(`^[a-f0-9]{16,}$|^[A-Za-z0-9_-]{20,}$`)

// AnomalyDetector отслеживает подозрительные паттерны:
// новые домены, DGA-подобные имена, DNS-утечки, beaconing, прокси.
type AnomalyDetector struct {
	mu sync.Mutex

	// Персистентная история доменов (~/.digger/known_domains.txt).
	historyPath     string
	knownDomains    map[string]bool // виденные когда-либо (растёт в течение сессии)
	baselineDomains map[string]bool // известные ДО запуска (из файла) — им доверяем
	historyDirty    bool

	// Дедуп отчётов: ключ → время последнего отчёта.
	reportedNew   map[string]time.Time
	reportedHash  map[string]time.Time
	reportedLeak  map[string]time.Time
	reportedProxy map[string]time.Time

	// Beaconing: DNS-запросы без последующих соединений.
	dnsOnlyDomains map[string]time.Time // домен → время первого запроса эпизода
	dnsOnlyCounts  map[string]int       // домен → число запросов в эпизоде
	beaconed       map[string]bool      // домен → beacon в эпизоде уже зафиксирован

	anomalies []AnomalyRecord
	printed   map[string]time.Time // напечатанные записи: ключ → время

	lastSweep time.Time
}

// AnomalyRecord — одна запись об аномалии.
type AnomalyRecord struct {
	Time    time.Time
	Kind    string // NEW | HASH | DNS-LEAK | BEACON | PROXY
	Domain  string
	Detail  string
	Process string
	SrcIP   string
}

func NewAnomalyDetector() *AnomalyDetector {
	ad := &AnomalyDetector{
		reportedNew:     make(map[string]time.Time),
		reportedHash:    make(map[string]time.Time),
		reportedLeak:    make(map[string]time.Time),
		reportedProxy:   make(map[string]time.Time),
		beaconed:        make(map[string]bool),
		dnsOnlyDomains:  make(map[string]time.Time),
		dnsOnlyCounts:   make(map[string]int),
		printed:         make(map[string]time.Time),
		knownDomains:    make(map[string]bool),
		baselineDomains: make(map[string]bool),
	}

	// История доменов. Если HOME недоступен — работаем без персистентности.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".digger")
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "digger: создать %s: %v\n", dir, err)
		}
		ad.historyPath = filepath.Join(dir, "known_domains.txt")
		ad.loadHistory()
	}

	return ad
}

// --- История ---

// loadHistory читает домены, известные до запуска.
func (ad *AnomalyDetector) loadHistory() {
	data, err := os.ReadFile(ad.historyPath)
	if err != nil {
		return // нет файла — все домены новые
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			ad.knownDomains[line] = true
			ad.baselineDomains[line] = true
		}
	}
}

// SaveHistory выгружает известные домены на диск, только если были изменения.
func (ad *AnomalyDetector) SaveHistory() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if !ad.historyDirty || ad.historyPath == "" {
		return
	}

	domains := make([]string, 0, len(ad.knownDomains))
	for d := range ad.knownDomains {
		domains = append(domains, d)
	}
	sort.Strings(domains) // стабильный файл — удобнее для diff

	var sb strings.Builder
	for _, d := range domains {
		sb.WriteString(d)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(ad.historyPath, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "digger: сохранить историю доменов: %v\n", err)
		return
	}
	ad.historyDirty = false
}

// --- Проверки (вызываются из горячего пути) ---

// CheckDomain возвращает флаги аномалий домена ("⚡NEW ⚠HASH") или "".
// isDNS: вызов из DNS-запроса — пополняет историю известных доменов.
func (ad *AnomalyDetector) CheckDomain(domain string, isDNS bool) string {
	if isIgnoredDomain(domain) {
		return ""
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	var flags []string

	// Хеш-подобная левая метка — признак DGA/трэкера.
	if labels := strings.Split(domain, "."); len(labels) > 1 {
		if hashLabelRe.MatchString(labels[0]) &&
			ad.shouldReport(ad.reportedHash, domain, now) {
			flags = append(flags, "⚠HASH")
			ad.record(now, "HASH", domain, "", "")
		}
	}

	if isDNS && !ad.knownDomains[domain] {
		if ad.shouldReport(ad.reportedNew, domain, now) {
			flags = append(flags, "⚡NEW")
			ad.record(now, "NEW", domain, "", "")
		}
		// Домен становится «известным»: NEW сработает один раз за всё время.
		ad.knownDomains[domain] = true
		ad.historyDirty = true
	}

	if len(flags) == 0 {
		return ""
	}
	return strings.Join(flags, " ")
}

// CheckDNSLeak: DNS-запрос ушёл мимо локального/LAN-резолвера.
// Дедуп — по IP резолвера (не по домену).
func (ad *AnomalyDetector) CheckDNSLeak(dstIP, domain string) string {
	if isLANIP(dstIP) {
		return ""
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	if !ad.shouldReport(ad.reportedLeak, dstIP, now) {
		return ""
	}
	ad.record(now, "DNS-LEAK", domain, "→ "+dstIP, "")

	return fmt.Sprintf("⚠DNS-LEAK → %s", dstIP)
}

// RecordDNSOnly запоминает DNS-запрос без последующего соединения:
// beaconMinCount+ запросов за beaconMinElapsed+ без соединений — beaconing.
func (ad *AnomalyDetector) RecordDNSOnly(domain string) {
	if isIgnoredDomain(domain) {
		return
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Доменам из истории (виденным ДО запуска) доверяем.
	// ВАЖНО: knownDomains здесь проверять нельзя — CheckDomain(isDNS=true)
	// добавляет домен в knownDomains при первом же запросе, и beaconing
	// не срабатывал бы никогда.
	if ad.baselineDomains[domain] {
		return
	}

	now := time.Now()
	if _, ok := ad.dnsOnlyDomains[domain]; !ok {
		ad.dnsOnlyDomains[domain] = now
	}
	ad.dnsOnlyCounts[domain]++

	count := ad.dnsOnlyCounts[domain]
	elapsed := now.Sub(ad.dnsOnlyDomains[domain])
	if count < beaconMinCount || elapsed < beaconMinElapsed {
		return
	}
	if ad.beaconed[domain] {
		return
	}
	ad.beaconed[domain] = true

	ad.record(now, "BEACON", domain,
		fmt.Sprintf("(%d DNS за %s без соединений)", count, elapsed.Truncate(time.Second)), "")
}

// RecordProxy регистрирует прокси-поток как аномалию.
func (ad *AnomalyDetector) RecordProxy(sni, remoteIP, process, reason string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	if !ad.shouldReport(ad.reportedProxy, sni+"|"+remoteIP, now) {
		return
	}
	ad.record(now, "PROXY", sni, fmt.Sprintf("→ %s (%s)", remoteIP, reason), process)
}

// MarkConnected: домен соединился — сбрасываем отслеживание beaconing.
func (ad *AnomalyDetector) MarkConnected(domain string) {
	if domain == "" {
		return
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	delete(ad.dnsOnlyDomains, domain)
	delete(ad.dnsOnlyCounts, domain)
	// Новый эпизод DNS-only сможет быть зафиксирован снова.
	delete(ad.beaconed, domain)
}

// --- Внутренние хелперы (вызываются под mu) ---

// shouldReport пропускает повторные события одного ключа в течение dedupWindow.
func (ad *AnomalyDetector) shouldReport(m map[string]time.Time, key string, now time.Time) bool {
	if t, ok := m[key]; ok && now.Sub(t) < dedupWindow {
		return false
	}
	m[key] = now
	return true
}

// record добавляет запись об аномалии.
func (ad *AnomalyDetector) record(now time.Time, kind, domain, detail, process string) {
	ad.anomalies = append(ad.anomalies, AnomalyRecord{
		Time:    now,
		Kind:    kind,
		Domain:  domain,
		Detail:  detail,
		Process: process,
	})
}

// sweep удаляет состояние, которое больше не может понадобиться.
// Без него anomalies/reported*/printed растут бесконечно.
func (ad *AnomalyDetector) sweep(now time.Time) {
	cutoff := now.Add(-recordMaxAge)

	// Записи хронологичны — отрезаем устаревший префикс.
	if len(ad.anomalies) > 0 && ad.anomalies[0].Time.Before(cutoff) {
		i := 0
		for ; i < len(ad.anomalies) && ad.anomalies[i].Time.Before(cutoff); i++ {
		}
		ad.anomalies = append([]AnomalyRecord(nil), ad.anomalies[i:]...)
	}

	for _, m := range []map[string]time.Time{
		ad.reportedNew, ad.reportedHash, ad.reportedLeak, ad.reportedProxy,
	} {
		for k, t := range m {
			if now.Sub(t) > recordMaxAge {
				delete(m, k)
			}
		}
	}

	// DNS-only эпизоды без активности дольше recordMaxAge.
	for d, t := range ad.dnsOnlyDomains {
		if now.Sub(t) > recordMaxAge {
			delete(ad.dnsOnlyDomains, d)
			delete(ad.dnsOnlyCounts, d)
			delete(ad.beaconed, d)
		}
	}

	for k, t := range ad.printed {
		if now.Sub(t) > recordMaxAge {
			delete(ad.printed, k)
		}
	}
}

// --- Чтение и вывод ---

// SetProcessForDomain приписывает процесс последней записи домена
// (процесс известен асинхронно, уже после детекта).
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

// CollectAnomalies возвращает записи за последние window, новые сверху.
// Попутно раз в sweepInterval чистит устаревшее состояние.
func (ad *AnomalyDetector) CollectAnomalies(window time.Duration) []AnomalyRecord {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	if now.Sub(ad.lastSweep) >= sweepInterval {
		ad.sweep(now)
		ad.lastSweep = now
	}

	cutoff := now.Add(-window)
	out := make([]AnomalyRecord, 0, len(ad.anomalies))
	for _, a := range ad.anomalies {
		if a.Time.After(cutoff) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// PrintAnomalies печатает аномалии за окно, каждую — один раз.
func (ad *AnomalyDetector) PrintAnomalies(window time.Duration) {
	records := ad.CollectAnomalies(window)
	if len(records) == 0 {
		return
	}

	// Отбор и форматирование — под локом, печать — вне,
	// чтобы не блокировать обработку пакетов.
	ad.mu.Lock()
	now := time.Now()
	lines := make([]string, 0, len(records))
	for _, a := range records {
		key := a.Kind + "|" + a.Domain + "|" + a.Detail
		if _, ok := ad.printed[key]; ok {
			continue
		}
		ad.printed[key] = now
		lines = append(lines, formatAnomaly(a))
	}
	ad.mu.Unlock()

	if len(lines) == 0 {
		return
	}

	fmt.Printf("\n=== ⚠ Подозрительное (новое) ===\n")
	for _, l := range lines {
		fmt.Println(l)
	}
	fmt.Println()
}

func anomalyKindLabel(kind string) string {
	switch kind {
	case "NEW":
		return "⚡NEW "
	case "HASH":
		return "⚠HASH"
	case "DNS-LEAK":
		return "⚠LEAK"
	case "BEACON":
		return "⚠BEACON"
	case "PROXY":
		return "⚠PROXY"
	default:
		return kind
	}
}

func formatAnomaly(a AnomalyRecord) string {
	proc := a.Process
	if proc == "" {
		proc = "?"
	}
	detail := ""
	if a.Detail != "" {
		detail = " " + a.Detail
	}
	return fmt.Sprintf("[%s] %-8s %-40s %s%s",
		a.Time.Format("15:04:05"), anomalyKindLabel(a.Kind),
		truncate(a.Domain, 40), proc, detail)
}

// isIgnoredDomain: reverse-DNS и пустые имена не анализируем.
func isIgnoredDomain(domain string) bool {
	return domain == "" ||
		strings.HasSuffix(domain, ".in-addr.arpa") ||
		strings.HasSuffix(domain, ".ip6.arpa")
}
