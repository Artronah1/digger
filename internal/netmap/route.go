package netmap

import (
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// RouteInfo — информация о маршруте к IP.
type RouteInfo struct {
	Interface string // eth0, tun0, br-lan
	SrcIP     string // адрес интерфейса
	Gateway   string // шлюз
	Table     string // номер таблицы (если есть)
	Mark      string // fwmark (если есть)
	Raw       string // сырой вывод ip route get
}

var (
	routeCache   = make(map[string]cachedRoute)
	routeCacheMu sync.Mutex
)

type cachedRoute struct {
	info     RouteInfo
	resolved time.Time
}

// LookupRoute возвращает маршрут к dstIP. Кэширует на 30 секунд.
func LookupRoute(dstIP string) RouteInfo {
	routeCacheMu.Lock()
	if c, ok := routeCache[dstIP]; ok && time.Since(c.resolved) < 30*time.Second {
		info := c.info
		routeCacheMu.Unlock()
		return info
	}
	routeCacheMu.Unlock()

	// Определяем версию IP
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return RouteInfo{}
	}

	var cmd *exec.Cmd
	if addr.Is6() {
		cmd = exec.Command("ip", "-6", "route", "get", dstIP)
	} else {
		cmd = exec.Command("ip", "route", "get", dstIP)
	}

	out, err := cmd.Output()
	if err != nil {
		return RouteInfo{}
	}

	info := parseRouteGet(string(out))
	info.Raw = strings.TrimSpace(string(out))

	routeCacheMu.Lock()
	routeCache[dstIP] = cachedRoute{info: info, resolved: time.Now()}
	routeCacheMu.Unlock()

	return info
}

// parseRouteGet разбирает вывод `ip route get`.
//
// Пример вывода:
//
//	192.168.1.1 dev eth0 src 192.168.1.79 uid 0
//	    cache
//
//	1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.79 uid 0
//	    cache
//
//	8.8.8.8 dev tun0 table 100 src 10.0.0.2 uid 0
//	    cache
func parseRouteGet(s string) RouteInfo {
	info := RouteInfo{}
	fields := strings.Fields(s)

	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "dev":
			if i+1 < len(fields) {
				info.Interface = fields[i+1]
			}
		case "src":
			if i+1 < len(fields) {
				info.SrcIP = fields[i+1]
			}
		case "via":
			if i+1 < len(fields) {
				info.Gateway = fields[i+1]
			}
		case "table":
			if i+1 < len(fields) {
				info.Table = fields[i+1]
			}
		case "mark":
			if i+1 < len(fields) {
				info.Mark = fields[i+1]
			}
		}
	}

	return info
}
