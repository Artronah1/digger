![Release](https://img.shields.io/github/v/release/Artronah1/digger)
![License](https://img.shields.io/github/license/Artronah1/digger)

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
- **Фильтры шума** (`-min-pkts`, `-hide-idle`, `-active-only`, `-dns-age`).

## Что показывает

- **Какой процесс / устройство → какой домен → сколько трафика.**
- **QUIC SNI** — какие домены видны в открытом виде даже при HTTPS/QUIC.
- **DNS ↔ SNI mismatch** — возможная DNS-подмена или MITM.
- **Утечки DNS** — если кто-то ходит напрямую к `8.8.8.8` или `1.1.1.1`.
- **Новые домены** (`⚡NEW`) — впервые замеченные в системе.
- **Хеш-подобные поддомены** (`⚠HASH`) — типичные трекеры (`b5b249a2d117...vip1...`).
- **Beaconing** (`⚠BEACON`) — домен запрашивается регулярно, но соединения нет.

## Флаги аномалий

| Флаг | Где | Что значит |
|---|---|---|
| `⚡NEW` | DNS-таблица | домен впервые замечен в системе |
| `⚠HASH` | DNS-таблица | левый label ≥16 символов hex/base64 — трекер или session ID |
| `⚠DNS-LEAK` | DNS-таблица | DNS-запрос к серверу вне LAN (например, `8.8.8.8`) |
| `⚠BEACON` | Раздел «Подозрительное» | домен запрашивается ≥3 раз за ≥30 сек **без соединений** |

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

## Сборка

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
