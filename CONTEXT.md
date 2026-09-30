## После v0.7.0 (2026-09-30)

### Рефакторинг Z.ai

- Pipeline: processData разбит на handleTLS / handleDNS / handleQUIC / handleVPN.
- currentView() — снимок разделяемых справочников (arpTable, localMACs, groupByDevice, appFilter) без лока.
- statsSnapshot() — копия CaptureStats без мьютекса (go vet).
- sweepLocked(now) + lastSweep — TTL-уборка в AnomalyDetector, DNSTable, DNSMapping, FlowTable.
- Двухфазный Enrich: I/O вне ft.mu, прогрев SNI-кэша.
- ReasonCode вместо русских строк в ProxySuspicion.
- spec-совместимые JA3 (GREASE исключён) и JA4 (SHA-256, сортировка, spec).

### Фиксы

- anomaly.go: инициализация knownDomains/baselineDomains (nil map → panic).
- anomaly_test.go: тест на загрузку истории.
- vpn.go: WireGuard-сигнатура по MAC2 (не путает с Telegram/QUIC).
- flows.go: vpnIPs не помечается для low-confidence.
- capture.go: isLANIP включает multicast (mDNS не считается DNS-LEAK).
- dns.go: DNS-over-TCP (2-байтовый префикс длины).
- quic_test.go: pn & 0xff (константный overflow).
- regression_test.go: убран дубль buildClientHello и bytes.
- json.go: schemaVersion 1 → 2, health: short_packets.
- baseline.go: SchemaVersion 1 → 2.

### Открытые вопросы (P0/P1)

P0:
- JA4 сверить с тест-векторами FoxIO (GREASE в счётчиках, ALPN «первые 2 символа», фильтр GREASE в sigalgs).
- -read: wall-clock vs timestamp пакета (AGE/timeline искажены).
- ClassifyFlow: obfs? low-confidence безусловно даёт ClassVPN — гейт по f.VPNConf != "low" (частично сделано, проверить).
- ECH-приоритет в extractSNI: SNI побеждает hasECH, но при реальном ECH outer-SNI — имя-прикрытие.
- fallback-порт процесса (socketsByPort) может приписать чужой процесс.
- Enrich /proc каждую секунду — разнести периоды (сокеты 5с, ARP 30с).

P1:
- printAnomaliesJSON: state vs event (emit-once).
- isPrivateIP / isLANIP дубликаты.
- Attribution.ProxyReason мёртв и противоречит resolveSNIAt.
- NamesForIPAt O(история) — нужен обратный индекс.
- hashLabelRe слишком широкий.
- SnapshotEvent дублирует HealthEvent.
- reason "no-observation" мёртвая ветка.

### Что дальше

- Шаг 2 DESIGN.md: Pipeline + Evidence + Classification как чистая функция.
- Или P0 (JA4 тест-векторы, -read timestamp).
- Или новые фичи (ICMP/ICMPv6, STUN/TURN, timeline потока).

### Файлы для чтения новым ИИ (в порядке)

1. capture.go       — точка входа, Run/processData/printAll
2. flows.go         — FlowTable, FlowStats, Aggregate, BuildDevices, Enrich
3. dns.go           — DNSTable, DNSMapping, parseDNS
4. anomaly.go       — AnomalyDetector, baselineDomains, BEACON
5. attribution.go   — BuildAttributions, BuildProxySuspicions
6. json.go          — все события JSON, schemaVersion=2
7. quic.go          — extractQUICSNI, readVarint, decryptInitial
8. sni.go           — extractSNI, extractJA3, extractJA4
9. geoip.go         — geoipCountry
10. pcap.go         — NewFromPCAP, RunFromPCAP
11. proxy.go        — resolveSNI, resolveSNIAt
12. vpn.go          — detectVPN
13. main.go         — флаги, baseline, диспетчер
14. baseline/*      — SchemaVersion=2
15. policy/*        — dns_resolvers, allow_direct, ipv6

### Конвенции

- Магические числа → константы (protoTCP, portDNS, anomalyWindow, flowMaxAge).
- Уборка: sweepLocked(now) + throttle lastSweep.
- Чтение разделяемых справочников вне лока — только через копию (view).
- Блокирующий I/O — никогда под ft.mu/dt.mu.
- Машинные коды причин (ReasonCode), не парсинг строк.

### Среда

- Go 1.27.1
- Зависимости: go-pcap, google/gopacket, gopacket/gopacket, oschwald/geoip2-golang/v2
- GeoIP: GeoLite2-Country.mmdb (относительный путь, не коммитится)
- Дома: enp6s0, на роутере: br-lan (OpenWrt aarch64)
