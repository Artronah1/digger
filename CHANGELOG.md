# Changelog

## [Unreleased] — 2026-09-28

### Добавлено

- **Детектор прокси/VPN-клиентов** (`⚠PROXY`)
  - Ловит потоки, где SNI не резолвится в удалённый IP.
  - Ловит процессы-прокси (mihomo, xray, sing-box, v2ray, trojan, shadowsocks, wireguard, openvpn и др.) на не-российские IP.
  - GeoIP-проверка через `GeoLite2-Country.mmdb`.
- **Раздел «⚠ Похоже на прокси/VPN-клиент»** в выводе — отдельная таблица после «Связки DNS ↔ SNI ↔ IP».
- **`sniResolvesToIP`** — резолв SNI через системный DNS с кэшем на 5 минут.

### Исправлено

- Детектор прокси больше не путает российские IP (Ozon, VK, Yandex) с прокси-фронтами.
- `BuildProxySuspicions` не возвращает `nil` при пустом `DNSMapping` — теперь проверка идёт через GeoIP и `sniResolvesToIP`.

### Известные ограничения

- `GeoLite2-Country.mmdb` может неверно определять страну для IP, зарегистрированных в РФ, но используемых как прокси.
- `sniResolvesToIP` требует, чтобы системный DNS был настроен и доступен (через `/etc/resolv.conf`).
