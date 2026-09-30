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

const (
	sniCacheTTL   = 5 * time.Minute
	sniCacheSweep = time.Minute
)

var (
	sniCache      = make(map[string]cachedResolve)
	sniCacheMu    sync.Mutex
	sniCacheSwept time.Time
)

type cachedResolve struct {
	ips      []string
	resolved time.Time
}

// resolveSNI резолвит домен через системный DNS. ВНИМАНИЕ: блокирующий
// вызов — из-под локов не звать (см. прогрев кэша в FlowTable.Enrich).
// IPv4 И IPv6: только IPv4 давал "not-resolved" для IPv6-only доменов
// и ложный класс proxy.
func resolveSNI(sni string) []string {
	now := time.Now()

	sniCacheMu.Lock()
	if c, ok := sniCache[sni]; ok && now.Sub(c.resolved) < sniCacheTTL {
		ips := c.ips
		sniCacheMu.Unlock()
		return ips
	}
	sniCacheMu.Unlock()

	ips := resolveSNIUncached(sni) // блокирующий DNS — без лока

	sniCacheMu.Lock()
	sniCache[sni] = cachedResolve{ips: ips, resolved: now}
	// Карта никогда не чистилась — росла бесконечно.
	if now.Sub(sniCacheSwept) > sniCacheSweep {
		sniCacheSwept = now
		for k, c := range sniCache {
			if now.Sub(c.resolved) > 2*sniCacheTTL {
				delete(sniCache, k)
			}
		}
	}
	sniCacheMu.Unlock()

	return ips
}

func resolveSNIUncached(sni string) []string {
	addrs, err := net.LookupIP(sni)
	if err != nil {
		return nil
	}
	ips := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.String())
	}
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

// ResolveResult — результат проверки SNI ↔ IP.
// Reason: "matched" | "different-ip" | "not-resolved" | "no-mapping".
// ("no-observation" из комментариев — мёртвое значение, никогда
// не возвращается; ветки под него в ClassifyFlow/attribution недостижимы.)
type ResolveResult struct {
	Matches     bool
	Reason      string
	ObservedIPs []string
}

// resolveSNIAt проверяет, был ли SNI актуален для IP на момент at.
func resolveSNIAt(sni, ip string, at time.Time, mapping *DNSMapping) ResolveResult {
	if mapping == nil {
		ips := resolveSNI(sni)
		if len(ips) == 0 {
			return ResolveResult{Reason: "not-resolved"}
		}
		for _, r := range ips {
			if r == ip {
				return ResolveResult{Matches: true, Reason: "matched", ObservedIPs: ips}
			}
		}
		return ResolveResult{Reason: "different-ip", ObservedIPs: ips}
	}

	// 1. Наблюдения DNS в момент at.
	names := mapping.NamesForIPAt(ip, at)
	for _, n := range names {
		if n == sni {
			return ResolveResult{Matches: true, Reason: "matched"}
		}
	}

	// 2. Наблюдений нет — резолвим сами (блокирующий вызов!).
	ips := resolveSNI(sni)
	if len(ips) == 0 {
		return ResolveResult{Reason: "not-resolved"}
	}
	for _, r := range ips {
		if r == ip {
			return ResolveResult{Matches: true, Reason: "matched", ObservedIPs: ips}
		}
	}

	// 3. Резолвится в другой IP — CDN-балансировка, не прокси.
	return ResolveResult{Matches: false, Reason: "different-ip", ObservedIPs: ips}
}
