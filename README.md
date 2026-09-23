# digger

Аудит сетевой приватности. Смотрит, что реально уходит с твоего устройства или роутера в интернет — и что из этого видно внешнему наблюдателю.

## Что умеет

- **Захват трафика** через libpcap (CGO-free, работает на ARM64).
- **TCP**: потоки, агрегация по SNI, retransmits, gaps, TCP-опции (MSS, window scale).
- **TLS SNI** — извлекается из ClientHello, включая фрагментированные.
- **QUIC SNI** — из Initial-пакетов (RFC 9001: HKDF, AES-GCM, header protection).
- **DNS** — запросы, ответы, маппинг `name → IP` и `IP → name`.
- **Связки DNS ↔ SNI ↔ IP** с детекцией mismatch.
- **Маппинг потоков на процессы** (через `/proc`).
- **ARP + OUI** — IP → MAC → вендор (для роутерного режима).
- **Тайминг-профиль** потока.
- **Фильтры шума** (`-min-pkts`, `-hide-idle`, `-active-only`, `-dns-age`).

## Что показывает

- **Какой процесс / устройство → какой домен → сколько трафика.**
- **Утечки DNS** — если кто-то ходит напрямую к `8.8.8.8` или `1.1.1.1`.
- **DNS ↔ SNI mismatch** — возможная DNS-подмена или MITM.
- **QUIC SNI** — какие домены видны в открытом виде даже при HTTPS/QUIC.

## Чего НЕ делает

- **Не расшифровывает TLS/QUIC payload** (после handshake).
- **Не заменяет VPN.**
- **Не обходит блокировки.**
- QUIC Initial — **не секрет** (RFC 9001), SNI из него может прочитать любой DPI.

## Сборка

### Локально (x86_64)

    go build -o digger .
    sudo setcap cap_net_raw+ep ./digger
    ./digger -i eth0 -f "tcp port 443"

### Под OpenWrt (aarch64)

    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o digger-arm64 .
    scp digger-arm64 root@192.168.1.1:/tmp/
    ssh root@192.168.1.1
    chmod +x /tmp/digger-arm64
    /tmp/digger-arm64 -i br-lan -router-mode -f "tcp port 443 or udp port 443"

## Флаги

| Флаг | Описание |
|---|---|
| `-i` | интерфейс для захвата (обязательно) |
| `-f` | BPF-фильтр |
| `-v` | подробный вывод пакетов |
| `-s` | snaplen (по умолчанию 65536) |
| `-min-pkts` | минимальное число пакетов в потоке |
| `-hide-idle` | скрывать потоки без активности > 30 сек |
| `-active-only N` | только потоки с активностью за N секунд |
| `-dns-age D` | показывать DNS-запросы не старше D |
| `-profile SNI` | тайминг-профиль для указанного SNI |
| `-netmap` | показать карту policy routing/firewall и выйти |
| `-router-mode` | режим роутера (LAN-клиенты) |

## Что видно снаружи

Даже с HTTPS/QUIC **внешний наблюдатель видит**:

- **SNI** — имя домена в открытом виде (TLS ClientHello, QUIC Initial).
- **DNS-запросы** — если не используется DoH/DoT/ECH.
- **IP-адреса и порты**, объёмы, тайминги.
- **TLS/QUIC-отпечатки** (JA3/JA4).

Если нужно **скрыть SNI**: ECH, VPN, obfuscation (reality, vision).

## Лицензия

MIT
