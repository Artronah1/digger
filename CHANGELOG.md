## [0.6.0] — 2026-09-29

### Добавлено

- **Baseline mode** — `-baseline create|check -baseline-file FILE`.
  - `create` — снимок доменов, процессов, устройств, JA3/JA4.
  - `check` — сравнение текущего с baseline. Diff по доменам, процессам, устройствам, JA3/JA4.
  - Событие `baseline_diff` в JSON.
- **LAN inventory** — секция `=== Устройства LAN ===` в `-router-mode`.
  - IP, MAC, Vendor (OUI), Hostname, Conns, Domains, OUT/IN.
  - Событие `device` в JSON.
- **`-group-by device`** — расширенный вывод.
  - Display, IP, MAC, Vendor, Hostname, TopDomains.
  - Счётчики Direct/Proxy/VPN/Unknown.
  - Событие `device_group` в JSON.
- **MAC на ПК** — `FlowTable.localMACs` из `net.InterfaceByName`.
- **Hostname** — `localHostname` для своего ПК.
- **JA4 fingerprint** — `ja4` в `flow`. Формат `t13d1517h2_hash_hash`.
- **Policy Auditor** — `-policy policy.yaml`:
  - `dns_resolvers` — `⚠POLICY-DNS→IP`.
  - `allow_direct` — домены, которые должны идти напрямую.
  - `ipv6` — разрешён или запрещён IPv6.
  - Секция `⚠ Policy Violations` в тексте.
  - Событие `policy_violation` в JSON.

### Изменено

- `Baseline` не пишет JA3/JA4 для ClassProxy/ClassVPN (у reality всегда разные).
- `Baseline` не пишет IP как «процесс» — только `f.Comm`.
- Baseline-текст только при `-output text`.

## [0.5.0] — 2026-09-29

### Добавлено

- **Policy Auditor** — `-policy policy.yaml`. Проверка реального поведения против ожидаемого.
  - `dns_resolvers` — разрешённые DNS-резолверы. `⚠POLICY-DNS→IP` в таблице DNS.
  - `allow_direct` — домены, которые должны идти напрямую. Если `class != direct` → violation.
  - `ipv6` — разрешён или запрещён IPv6-трафик.
  - Секция `⚠ Policy Violations` в текстовом выводе.
  - Событие `policy_violation` в JSON: rule, expected, actual, detail.
- **JA3 fingerprint** — TLS-отпечаток клиента (MD5 от version, ciphers, extensions, curves, formats). Поле `ja3` в `flow`.
- **ECH detection** — `extractSNI` возвращает `ECHSentinel` при extension `0xfe0d`. `RECON = ech`, `CLASS = direct`.
- **PCAP reading** — флаг `-read file.pcap`. `processData(data []byte)` работает и для live, и для файла.
- **PCAP regression suite** — `internal/capture/testdata/dns.pcap` + `regression_test.go`.
- **`dns_observation`** — наблюдения DNS с TTL. Фильтр по `-dns-age`.
- **IPv6 route** — `netmap.LookupRoute` определяет версию IP, использует `ip -6 route get`.
- **`Capture.SetQuiet`** — отключение вывода в тестах.

### Изменено

- `process(pkt pcap.Packet)` → `processData(data []byte)`.
- SNI: убран `isOutbound` — ClientHello всегда `dstPort = 443`.
- `ClassifyFlow` вызывается в `Enrich` для `ClassUnknown`.
- `AddObservation` не выходит до `parseDNSResponse`.
- `SetFlags` в `DNSTable` ищет по `udp/53`, `tcp/53`, `mdns`.

### Исправлено

- `io.ErrUnexpectedEOF` в PCAP — не считается ошибкой.
- `dns_observation` создаётся для CNAME/NXDomain/HTTPS без A.
- `SetFlags` находит флаги для `mdns` (5353).

## [0.4.0] — 2026-09-29

### Добавлено

- **Classification** — итоговая классификация каждого потока: `DIRECT` / `PROXY` / `VPN` / `UNKNOWN`.
  - `CLASS` в текстовом выводе, `classification` в JSON.
  - VPN-ноды (`mihomo`, `xray`) определяются по процессу + SNI, который не резолвится.
  - `vpnIPs` — IP VPN-нод запоминаются, все потоки к ним получают `vpn`.
- **Route attribution** — для каждого потока виден интерфейс, через который он уходит.
  - `ROUTE` в текстовом выводе, `route_interface` / `route_src_ip` / `route_gateway` / `route_table` в JSON.
  - `netmap.LookupRoute()` через `ip route get`, кэш 30 секунд.
- **`Enrich`** — заполняет `Route` для каждого потока раз в секунду.

### Изменено

- `AppendPayload` больше не проверяет `Comm` (на момент вызова он ещё пуст).
- `Enrich` выполняет классификацию VPN-нод.

### Исправлено

- Ложное срабатывание `CLASS = vpn` для CDN (`resolveSNIAt` возвращает `different-ip` → `direct`).

## [0.3.0] — 2026-09-28

### Добавлено

- **Capture Health** — счётчики `received`, `processed`, `truncated`, `decode_errors`, `no_ip_layer`. Флаг `quality: complete/incomplete`. Разделение горячего пути и печати: `process()` в отдельной горутине от `printLoop()`. Под нагрузкой (31 486 пакетов) `received == processed` — ноль потерь.
- **DNS с временем** — `DNSObservation` с `observed_at`, `expires_at`, `TTL`. `AddObservation`, `NamesForIPAt` — имена актуальны на момент соединения. `parseDNSResponseTTL` — минимальный TTL из ответа.
- **`resolveSNIAt`** — возвращает причину (`matched` / `different-ip` / `not-resolved` / `no-observation`), а не вердикт. Убирает ложное срабатывание на `fonts.googleapis.com` (CDN-балансировка).
- **`reconstruction_status`** — `complete` / `partial` / `gap` / `empty` / `unknown`. Поле `Recon` в `FlowStats`. Колонка `RECON` в текстовом выводе.
- **JSON output** (`-output json`) — JSONL со `schema: 1`. Восемь типов событий:
  - `snapshot` — iface, filter, snaplen, version, uptime
  - `health` — счётчики Capture Health + quality
  - `flow` — label, sni, process, recon, conns, bytes, retransmits, gaps
  - `dns` — name, qtype, src/dst, transport, count, flags
  - `attribution` — status ✓/~/⚠/✗/?, dns_names, reason
  - `proxy_suspicion` — reason, confidence (process / dns-mismatch / heuristic)
  - `proxy_process` — process, conns, bytes, remote_ips
  - `anomaly` — NEW / HASH / BEACON / PROXY / DNS-LEAK
- **`diggerVersion()`** — версия через `runtime/debug.ReadBuildInfo()`, подтягивается из git-тега.

### Изменено

- `SetShowPTR` сохраняет флаг в `Capture.showPTR` — PTR-запросы скрыты в JSON.
- `printAll()` разветвляется: `text` или `json`.
- `BuildProxySuspicions` использует `resolveSNIAt` — причину, а не вердикт.

### Исправлено

- Ложное срабатывание на `fonts.googleapis.com` (CDN-балансировка, не прокси).
- Ложное срабатывание на `yt3.ggpht.com` (фильтр IPv4 в `resolveSNI`).
- Дубли `PROCESS = ?` в таблице прокси.

## [0.2.0] — 2026-09-28
...
