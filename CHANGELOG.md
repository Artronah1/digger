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
