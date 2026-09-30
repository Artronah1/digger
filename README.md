![Release](https://img.shields.io/github/v/release/Artronah1/digger)
![License](https://img.shields.io/github/license/Artronah1/digger)
![Go](https://img.shields.io/badge/Go-1.21+-blue)

# digger

Аудит сетевой приватности. Смотрит, что реально уходит с твоего устройства или роутера в интернет — и что из этого видно внешнему наблюдателю.

Работает на Linux (x86_64) и OpenWrt (aarch64), без CGO.

## Что умеет

- **Захват трафика** через libpcap (CGO-free, `go-pcap`).
- **TCP**: потоки, агрегация по SNI, retransmits, gaps, TCP-опции (MSS, window scale), тайминг-профиль.
- **TLS SNI** — извлекается из ClientHello, включая фрагментированные (склейка нескольких TCP-сегментов).
- **QUIC SNI** — из Initial-пакетов (RFC 9001): Long Header, HKDF-Expand-Label, AES-GCM, header protection, CRYPTO-frames.
- **Связка client/server QUIC Initial** — через SCID клиента → DCID клиента. Серверные Initial тоже расшифровываются.
- **DNS** — запросы и ответы, маппинг `name → IP` и `IP → name`.
- **Связки DNS ↔ SNI ↔ IP** — с детекцией mismatch.
- **Маппинг потоков на процессы** — через `/proc/net/tcp`, `/proc/[pid]/fd`.
- **ARP + OUI** — IP → MAC → вендор (для роутерного режима).
- **Группировка по приложениям / устройствам** — `-group-by app`, `-group-by device`.
- **Детектор аномалий** — история доменов, хеш-подобные поддомены, утечки DNS, beaconing.
- **Детектор прокси/VPN-клиентов** — находит потоки, похожие на прокси (mihomo, xray, sing-box, v2ray, trojan и др.) по имени процесса и резолву SNI.
- **GeoIP-проверка** — `GeoLite2-Country` для определения страны IP (используется, чтобы не путать российские IP с прокси).
- **Фильтры шума** (`-min-pkts`, `-hide-idle`, `-active-only`, `-dns-age`).
- **JSONL output** (`-output json`) — восемь типов событий: `snapshot`, `health`, `flow`, `dns`, `attribution`, `proxy_suspicion`, `proxy_process`, `anomaly`. Схема `schema: 1`.
- **Route attribution** — для каждого потока виден интерфейс, через который он уходит (`eth0`, `tun0`, `br-lan`), и src-адрес.
- **Classification** — `DIRECT` / `PROXY` / `VPN` / `UNKNOWN` для каждого потока. VPN-ноды (mihomo, xray) определяются по процессу + SNI.
- **Policy Auditor** (`-policy policy.yaml`) — проверка реального поведения против ожидаемого.
- **JA3 fingerprint** — TLS-отпечаток клиента.
- **ECH detection** — определение Encrypted ClientHello.
- **PCAP reading** (`-read file.pcap`) — анализ сохранённых захватов.

## Что показывает

- **Какой процесс / устройство → какой домен → сколько трафика.**
- **QUIC SNI** — какие домены видны в открытом виде даже при HTTPS/QUIC.
- **DNS ↔ SNI mismatch** — возможная DNS-подмена или MITM.
- **Утечки DNS** — если кто-то ходит напрямую к `8.8.8.8` или `1.1.1.1`.
- **Новые домены** (`⚡NEW`) — впервые замеченные в системе.
- **Хеш-подобные поддомены** (`⚠HASH`) — типичные трекеры (`b5b249a2d117...vip1...`).
- **Beaconing** (`⚠BEACON`) — домен запрашивается регулярно, но соединения нет.
- **Прокси-трафик** (`⚠PROXY`) — потоки, где SNI не резолвится в удалённый IP, или процесс — известный прокси-клиент, а IP не российский.
- **Capture Health** — счётчики `received`/`processed`/`truncated`/`decode errors`. Флаг `quality: complete/incomplete`. Под нагрузкой `received == processed` — ноль потерь.
- **`RECON`** — насколько полно реконструирован payload: `✓` (complete), `⚠part` (partial), `⚠gap` (gap), `?` (unknown). Видно, где SNI **точно** извлекли, а где ClientHello не видели.
- **Классификация потока** (`CLASS`) — `direct` / `proxy` / `vpn` / `unknown`. Видно, что идёт напрямую, что через прокси, что в VPN-туннель.
- **Маршрут** (`ROUTE`) — через какой интерфейс уходит поток.

### VPN-детект: ограничения

- **OpenVPN-over-TCP на 443** — не детектится (маскируется под HTTPS, без разбора payload не отличим от TLS).
- **OpenVPN-over-UDP на 443** — не детектится (QUIC short header `0x40-0x7F` даёт ложные opcode).
- **WireGuard** — 148/92 байта, sender index != 0, MAC2 = 0.
- **IKEv2** — UDP/500, UDP/4500, версия 0x20 в байте 17.

**DNSCrypt/DoH/DoT** — не VPN, не прокси. `digger` пропускает их в `BuildProxySuspicions`.

## Флаги аномалий

| Флаг | Где | Что значит |
|---|---|---|
| `⚡NEW` | DNS-таблица | домен впервые замечен в системе |
| `⚠HASH` | DNS-таблица | левый label ≥16 символов hex/base64 — трекер или session ID |
| `⚠DNS-LEAK` | DNS-таблица | DNS-запрос к серверу вне LAN (например, `8.8.8.8`) |
| `⚠BEACON` | Раздел «Подозрительное» | домен запрашивается ≥3 раз за ≥30 сек **без соединений** |
| `⚠PROXY` | Раздел «Похоже на прокси/VPN-клиент» + «Подозрительное» | SNI не резолвится в IP (**прокси-фронт**) или процесс-прокси на не-российский IP |

История доменов сохраняется в `~/.digger/known_domains.txt`. Удалить — `rm ~/.digger/known_domains.txt`.

## Раздел «⚠ Подозрительное»

Каждые 5 секунд после основных таблиц выводится **сводка новых аномалий** (без повторов):

```
=== ⚠ Подозрительное (новое) ===
[18:51:41] ⚡NEW     accounts.youtube.com                icecat(70573)
[18:51:38] ⚡NEW     ws.chatgpt.com                      icecat(70573)
[18:41:50] ⚠BEACON  example.org                         ? (7 DNS за 30s без соединений)
```

**Процесс** определяется тремя способами:
1. Прямое совпадение SNI.
2. По IP через `DNSMapping`.
3. Кэш из предыдущих выводов.

Если процесс не найден — `?`. **`-show-ptr`** — по умолчанию PTR-запросы **скрыты** (это служебный резолв самого `digger`).

## Статусы связок DNS ↔ SNI ↔ IP

| Статус | Значение |
|---|---|
| `✓` | SNI входит в DNS-имена этого IP — совпадает |
| `~` | DNS есть, SNI не поймали (сессия старая или ClientHello не в первом пакете) |
| `?` | ни SNI, ни DNS — неизвестный поток |
| `✗` | SNI есть, но DNS не подтверждает (кэш браузера или CDN-балансировка) |
| `⚠` | SNI есть, DNS отдал другой домен — возможная подмена (в норме не встречается) |

## Чего НЕ делает

- **Не расшифровывает TLS/QUIC payload** (после handshake — session keys).
- **Не заменяет VPN.**
- **Не обходит блокировки.**
- **QUIC Initial — не секрет** (RFC 9001, ключи выводятся из DCID и публичной соли). SNI из него может прочитать любой DPI.
- **Не блокирует прокси.** Только показывает, что трафик идёт через прокси-клиент.
- **Не определяет «VPN это или нет» по содержимому.** Только по косвенным признакам: SNI, DNS, GeoIP, имя процесса.
- **Не классифицирует** поток как «direct/proxy/vpn» автоматически — только показывает признаки.

## Сборка

> **Важно:** `setcap cap_net_raw+ep ./digger` даёт право захвата без sudo. 
> Не запускайте через `sudo` — иначе `$HOME` сбросится на `/root`, и 
> история доменов (`~/.digger/known_domains.txt`) будет читаться/писаться 
> не из вашего домашнего каталога.

### GeoIP база (опционально)

Для проверки страны IP используется `GeoLite2-Country.mmdb`. Скачать:

```bash
wget -O GeoLite2-Country.mmdb.gz \
  "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz"
gunzip GeoLite2-Country.mmdb.gz
```

Положить рядом с бинарником `digger` или указать путь в `internal/capture/geoip.go`.

### Локально (x86_64)

```
go build -o digger .
sudo setcap cap_net_raw+ep ./digger
./digger -i eth0 -f "tcp port 443 or udp port 443 or udp port 53"
```

`setcap cap_net_raw+ep` даёт бинарнику право захватывать пакеты **без sudo**.

### Под OpenWrt (aarch64)

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o digger-arm64 .
scp digger-arm64 root@192.168.1.1:/tmp/
ssh root@192.168.1.1
chmod +x /tmp/digger-arm64
/tmp/digger-arm64 -i br-lan -router-mode -f "tcp port 443 or udp port 443"
```

## Примеры запуска

### Простой: только HTTPS-трафик на ПК

```
./digger -i enp6s0 -f "tcp port 443"
```

### С фильтрами шума (использовался в разработке)

```
./digger -i enp6s0 -f "tcp port 443 or udp port 443 or udp port 53" -active-only 5 -dns-age 60s
```

- `-f "tcp port 443 or udp port 443 or udp port 53"` — TCP/443 (HTTPS), UDP/443 (QUIC), UDP/53 (DNS).
- `-active-only 5` — только потоки с активностью за 5 секунд.
- `-dns-age 60s` — DNS за последнюю минуту.

### На роутере (все устройства LAN)

```
/tmp/digger-arm64 -i br-lan -router-mode -f "tcp port 443 or udp port 443 or udp port 53" -active-only 5 -dns-age 60s
```

### Группировка по приложениям

Флаг `-group-by app` группирует потоки по **процессу** (на ПК) или **устройству** (на роутере):

```
./digger -i enp6s0 -f "tcp port 443" -active-only 5 -group-by app
```

```
=== Приложения / устройства (3) ===
APP                            CONNS  DOMAINS        OUT         IN   AGE
icecat(70573)                     45       15     2.3 MB    15.4 MB   30s
xray(4255)                        38       22     0.5 MB     3.2 MB   45s
AyuGram(1891)                     12        3     0.1 MB     0.8 MB   20s
```

Флаг `-app <имя>` показывает **только** это приложение:

```
./digger -i enp6s0 -f "tcp port 443" -active-only 5 -group-by app -app icecat
```

### Группировка по устройствам (роутер)

```
/tmp/digger-arm64 -i br-lan -router-mode -f "tcp port 443" -group-by device
```

```
=== Приложения / устройства (2) ===
APP                            CONNS  DOMAINS        OUT         IN   AGE
192.168.1.128 (random-mac)        45       15     2.3 MB    15.4 MB   30s
192.168.1.2 (Realtek)             23        8     0.5 MB     3.2 MB   45s
```

## Classification и Route

Каждый поток получает **классификацию** и **маршрут**:

| Колонка | Значения | Что значит |
|---|---|---|
| `RECON` | `✓` / `⚠part` / `⚠gap` / `?` / `·` | Насколько полно реконструирован payload |
| `CLASS` | `direct` / `proxy` / `vpn` / `unknown` | Куда идёт поток |
| `ROUTE` | `eth0` / `tun0` / `br-lan` / … | Через какой интерфейс |

**Classification:**

- **`direct`** — SNI есть, DNS совпал (или CDN-балансировка).
- **`proxy`** — SNI не резолвится, или процесс-прокси без SNI.
- **`vpn`** — процесс-прокси (`mihomo`, `xray`) + SNI не резолвится → VPN-нода. Все потоки к тому же IP — тоже `vpn`.
- **`unknown`** — недостаточно данных.

## Policy Auditor

`-policy policy.yaml` — проверка реального поведения против ожидаемого.

```yaml
# policy.yaml
dns_resolvers:
  - 192.168.1.1
allow_direct:
  - ozon.ru
  - vk.com
ipv6: false
```
## Baseline mode

`-baseline create|check -baseline-file FILE`.

**Create** — снимок нормального поведения:

```bash
sudo ./digger -i eth0 -baseline create -baseline-file baseline.json
```

**Check** — сравнение текущего с baseline:

```bash
sudo ./digger -i eth0 -baseline check -baseline-file baseline.json
```

**Что сравнивается:** домены, процессы, устройства, JA3/JA4.

**JSON:** событие `baseline_diff` с `diff_kind`:
- `new_domain`, `removed_domain`,
- `new_process`, `removed_process`,
- `new_device`, `removed_device`,
- `changed_ja3`, `changed_ja4`, `new_ja3`, `new_ja4`.

```bash
sudo ./digger -i eth0 -baseline check -baseline-file baseline.json -output json | \
  jq -c 'select(.kind=="baseline_diff")'
```

**Правила:**

| Правило | Что проверяет |
|---|---|
| `dns_resolvers` | DNS только через разрешённые резолверы → `⚠POLICY-DNS→IP` |
| `allow_direct` | Домены, которые должны идти напрямую. Если класс ≠ direct → violation |
| `ipv6` | Разрешён или запрещён IPv6-трафик |

**Секция** `⚠ Policy Violations` в тексте. **Событие** `policy_violation` в JSON.

## JA3 fingerprint

`ja3` в JSON-событии `flow` — TLS-отпечаток клиента. MD5 от version, ciphers, extensions, curves, formats.

Один и тот же клиент (Firefox) → один JA3 для разных SNI.

**Route attribution:** используется `ip route get <ip>`, кэш 30 секунд. Видно, через какой интерфейс уходит поток — `eth0` (прямо), `tun0` (VPN), `br-lan` (LAN).

Пример:

```
PROCESS         SNI / REMOTE              RECON  CLASS    ROUTE    PROTO
mihomo(1124) memescollection.com  ✓      vpn      eth0     TCP
mihomo(1124)    62.233.43.43      ?      vpn      eth0     TCP
icecat(19007)   ws.chatgpt.com            ✓      direct   eth0     TCP
```

## Флаги

| Флаг | Описание |
|---|---|
| `-i` | **интерфейс** для захвата (обязательно). Узнать: `ip -br link` |
| `-f` | **BPF-фильтр** — какие пакеты захватывать. Синтаксис как у `tcpdump` |
| `-v` | подробный вывод пакетов (много шума) |
| `-s` | **snaplen** — сколько байт захватывать от каждого пакета. По умолчанию `65536` |
| `-min-pkts` | минимальное число пакетов в потоке |
| `-hide-idle` | скрывать потоки без активности > 30 сек |
| `-active-only N` | только потоки с активностью за N секунд |
| `-dns-age D` | показывать DNS-запросы не старше D (0 = все) |
| `-profile SNI` | тайминг-профиль для указанного SNI |
| `-netmap` | показать карту policy routing/firewall и выйти |
| `-router-mode` | режим роутера (LAN-клиенты как outbound) |
| `-show-ptr` | показывать PTR-запросы в DNS-таблице |
| `-log FILE` | писать вывод в файл (одновременно в stdout) |
| `-group-by app\|device` | группировать по приложениям или устройствам |
| `-app NAME` | фильтр по имени приложения/устройства |
| `-output text\|json` | формат вывода: текстовый (по умолчанию) или JSONL |
| `-policy FILE` | файл политики (policy.yaml) для аудита |
| `-baseline create\|check` | режим baseline |
| `-baseline-file FILE` | файл baseline (по умолчанию baseline.json) |

## JSON output

`-output json` печатает **JSONL** — по одному JSON-объекту на строку. Схема версионируется (`schema: 1`).

Восемь типов событий:

| `kind` | Что |
|---|---|
| `snapshot` | мета о запуске: iface, filter, snaplen, version, uptime |
| `health` | счётчики Capture Health + quality |
| `flow` | агрегированный поток: label, sni, process, recon, **classification**, **route_interface**, **route_src_ip**, conns, bytes |
| `dns` | DNS-запрос: name, qtype, src/dst, transport, count, flags |
| `attribution` | связка DNS ↔ SNI ↔ IP: status (✓/~/⚠/✗/?), dns_names, reason |
| `proxy_suspicion` | подозрение на прокси: reason, confidence (process / dns-mismatch / heuristic) |
| `proxy_process` | агрегат по процессу-прокси: process, conns, bytes, remote_ips |
| `anomaly` | аномалия: NEW / HASH / BEACON / PROXY / DNS-LEAK |

### Поля `flow`

```json
{
  "schema": 1,
  "ts": "2026-09-29T06:19:23Z",
  "kind": "flow",
  "cycle": 1,
  "label": "memescollection.com",
  "sni": "memescollection.com",
  "process": "mihomo(1124)",
  "proto": "TCP",
  "recon": "complete",
  "classification": "vpn",
  "route_interface": "eth0",
  "route_src_ip": "192.168.1.79",
  "route_gateway": "",
  "route_table": "",
  "conns": 5,
  "packets_out": 100,
  "bytes_out": 35800,
  "packets_in": 50,
  "bytes_in": 7800,
  "retransmits": 0,
  "gaps": 0,
  "age_sec": 12,
  "first_seen": "2026-09-29T06:19:11Z",
  "last_seen": "2026-09-29T06:19:23Z"
}
```
Пример:

```bash
sudo ./digger -i eth0 -f "tcp port 443" -output json | jq -c 'select(.kind=="flow") | {label, classification, route_interface}'
```

```json
{"label":"**************","classification":"vpn","route_interface":"eth0"}
{"label":"ws.chatgpt.com","classification":"direct","route_interface":"eth0"}
{"label":"**************","classification":"unknown","route_interface":"eth0"}
```

Пример:

```bash
sudo ./digger -i eth0 -f "tcp port 443" -output json | jq -c 'select(.kind=="flow") | {label, process, recon, classification}'
```

```json
{"label":"ws.chatgpt.com","process":"icecat(19007)","recon":"complete"}
{"label":"172.64.148.235","process":"icecat(19007)","recon":"unknown"}
```

Запись в файл:

```bash
sudo ./digger -i eth0 -output json -log /tmp/audit.jsonl
```

Анализ:

```bash
# Все прокси-процессы
jq 'select(.kind=="proxy_process")' /tmp/audit.jsonl

# Потоки, где SNI не резолвится
jq 'select(.kind=="proxy_suspicion" and .confidence=="dns-mismatch")' /tmp/audit.jsonl

# Проверка, не терялись ли пакеты
jq 'select(.kind=="health" and .quality=="incomplete")' /tmp/audit.jsonl
```

### Что такое BPF-фильтр

**BPF** (Berkeley Packet Filter) — **язык описания фильтров** для захвата пакетов. **Компилируется ядром** и работает **до** того, как пакет попадёт в программу. Это **очень быстро** — не мы фильтруем, а **ядро**.

Синтаксис тот же, что у `tcpdump`:

- `tcp` — только TCP
- `udp` — только UDP
- `port 443` — порт 443 (и src, и dst)
- `host 1.1.1.1` — конкретный IP
- `net 192.168.1.0/24` — подсеть
- `and`, `or`, `not` — логические операторы
- `"tcp port 443 or udp port 443"` — TCP/443 **или** UDP/443

Если фильтр **не задан** — захватываются **все** пакеты. Таблица **быстро растёт**.

### Что такое snaplen

**snaplen** (snapshot length) — **сколько байт каждого пакета сохранять**.

- **65536** (по умолчанию) — сохраняем **весь** пакет.
- **128** — только заголовки (Ethernet + IP + TCP), без payload.

Для **аудита приватности** нужен **полный** snaplen — иначе не поймаем SNI из TLS ClientHello (он в payload).

## Пример вывода

```
=== Группы по SNI (9, скрыто: 2 pkts / 0 idle / 22 active / 0 шум) ===
PROCESS              SNI / REMOTE                     PROTO CONNS    PKT/S   AVG_SZ        OUT         IN RETR GAPS   AGE
icecat(70573)        rr1---sn-4g5edndr.googlevideo.c… TCP       1      2.1     6695     9.3 KB   703.4 KB    0    0   51s
icecat(70573)        chat.z.ai                        TCP       4      3.0     1492    21.9 KB   160.2 KB    0    0   42s
192.168.1.2          r.googlevideo.com                UDP       5     99.7      881   196.8 KB     4.1 MB    0    0   51s

=== Связки DNS ↔ SNI ↔ IP (37) ===
✓ совпало: 22   ⚠ не совпало: 0   ? без DNS: 9

LOCAL              REMOTE IP        SNI                              DNS (names для этого IP)         STATUS AGE
192.168.1.2:44320  163.181.131.240  chat.z.ai                        chat.z.ai                        ✓      40s
192.168.1.2:41146  185.15.59.224    —                                auth.wikimedia.org               ~      38s
192.168.1.2:43612  163.181.254.184  z-cdn-media.chatglm.cn           —                                ✗      39s

=== DNS-запросы (62) ===
SRC              NAME                                     QTYPE  VIA      TO               COUNT AGE   FLAGS
192.168.1.2      chat.z.ai                                HTTPS  udp/53   192.168.1.1          2 50s   ⚡NEW
192.168.1.2      ocsp.globalsign.com                      A      udp/53   192.168.1.1          1 45s   ⚡NEW
192.168.1.2      example.com                              A      udp/53   8.8.8.8              1 3s    ⚠DNS-LEAK → 8.8.8.8
```

## Что видно снаружи

Даже с HTTPS/QUIC **внешний наблюдатель видит**:

- **SNI** — имя домена в открытом виде (TLS ClientHello, QUIC Initial).
- **DNS-запросы** — если не используется DoH/DoT/ECH.
- **IP-адреса и порты**, объёмы, тайминги.
- **TLS/QUIC-отпечатки** (JA3/JA4).

Если нужно **скрыть SNI**: ECH (Encrypted ClientHello), VPN, obfuscation (`reality`, `xtls-rprx-vision`).

## Часть экосистемы

`digger` — один из инструментов для настройки приватной домашней сети на OpenWrt. **Планируется** также:

- демон kill-switch для OpenWrt,
- гайд по настройке роутера,
- утилита для управления DNSCrypt-релеями.

Все проекты — открытые и дополняют друг друга. `digger` — **инструмент наблюдения**: показывает, что реально уходит в интернет, помогает понять, где есть утечки.

## Лицензия

MIT
