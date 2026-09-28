package capture

import (
	"net"
	"strings"
	"sync"
	"time"
)

// knownProxyComms — процессы, которые сами по себе означают прокси.
// Сравнение регистронезависимое, по подстроке в comm.
var knownProxyComms = []string{
	"mihomo", "clash", "clash-meta", "clash.meta",
	"xray", "v2ray", "v2fly", "sing-box", "singbox",
	"hysteria", "hysteria2", "tuic", "naive",
	"trojan", "trojan-go",
	"shadowsocks", "ss-local", "sslocal", "ss-server", "ssserver",
	"wireguard", "wg-quick", "openvpn", "openconnect",
	"tun2socks", "tun2proxy", "hev-socks5-tunnel",
	"redsocks", "gost", "frpc", "frps",
}

func looksLikeProxyProcess(comm string) bool {
	if comm == "" {
		return false
	}
	c := strings.ToLower(comm)
	for _, p := range knownProxyComms {
		if strings.Contains(c, p) {
			return true
		}
	}
	return false
}

var (
	sniCache   = make(map[string]cachedResolve)
	sniCacheMu sync.Mutex
)

type cachedResolve struct {
	ips      []string
	resolved time.Time
}

// resolveSNI резолвит домен через системный DNS и возвращает список IP.
// Кэширует на 5 минут.
func resolveSNI(sni string) []string {
	sniCacheMu.Lock()
	if c, ok := sniCache[sni]; ok && time.Since(c.resolved) < 5*time.Minute {
		ips := c.ips
		sniCacheMu.Unlock()
		return ips
	}
	sniCacheMu.Unlock()

	addrs, err := net.LookupIP(sni)
	if err != nil {
		addrs = nil
	}
	var ips []string
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			ips = append(ips, v4.String())
		}
	}

	sniCacheMu.Lock()
	sniCache[sni] = cachedResolve{ips: ips, resolved: time.Now()}
	sniCacheMu.Unlock()

	return ips
}

// sniResolvesToIP проверяет, резолвится ли SNI в указанный IP.
func sniResolvesToIP(sni, ip string) bool {
	ips := resolveSNI(sni)
	for _, resolved := range ips {
		if resolved == ip {
			return true
		}
	}
	return false
}
