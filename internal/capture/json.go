package capture

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

// schemaVersion — версия схемы JSON. При breaking changes — увеличивать.
const schemaVersion = 1

func diggerVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}

// Event — общая обёртка для всех JSON-событий.
type Event struct {
	Schema int    `json:"schema"`
	TS     string `json:"ts"`
	Kind   string `json:"kind"`
}

func newEvent(kind string) Event {
	return Event{
		Schema: schemaVersion,
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Kind:   kind,
	}
}

// printJSON сериализует и печатает событие одной строкой.
func printJSON(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// SnapshotEvent — мета о запуске.
type SnapshotEvent struct {
	Event
	Cycle   int    `json:"cycle"`
	Iface   string `json:"iface"`
	Filter  string `json:"filter"`
	Snaplen int    `json:"snaplen"`
	Version string `json:"version"`
	Uptime  int64  `json:"uptime_sec"`
}

// HealthEvent — счётчики Capture Health.
type HealthEvent struct {
	Event
	Cycle            int    `json:"cycle"`
	Iface            string `json:"iface"`
	Filter           string `json:"filter"`
	Snaplen          int    `json:"snaplen"`
	UptimeSec        int64  `json:"uptime_sec"`
	PacketsReceived  uint64 `json:"packets_received"`
	PacketsProcessed uint64 `json:"packets_processed"`
	PacketsTruncated uint64 `json:"packets_truncated"`
	DecodeErrors     uint64 `json:"decode_errors"`
	NoIPLayer        uint64 `json:"no_ip_layer"`
	BytesReceived    uint64 `json:"bytes_received"`
	BytesProcessed   uint64 `json:"bytes_processed"`
	Quality          string `json:"quality"`
}

// FlowEvent — один агрегированный поток.
type FlowEvent struct {
	Event

	Cycle             int    `json:"cycle"`
	Label             string `json:"label"` // Идентификатор потока (SNI, Hostname или IP)
	Process           string `json:"process"`
	SNI               string `json:"sni,omitempty"` // Только если Label является настоящим SNI
	Classification    string `json:"classification"`
	Hostname          string `json:"hostname,omitempty"` // Если Label является hostname
	RemoteIP          string `json:"remote_ip,omitempty"`
	RemotePort        uint16 `json:"remote_port,omitempty"`
	Proto             string `json:"proto"`
	Recon             string `json:"recon,omitempty"`
	Conns             int    `json:"conns"`
	PacketsOut        uint64 `json:"packets_out"`
	BytesOut          uint64 `json:"bytes_out"`
	PacketsIn         uint64 `json:"packets_in"`
	BytesIn           uint64 `json:"bytes_in"`
	Retransmits       uint64 `json:"retransmits"`
	Gaps              uint64 `json:"gaps"`
	AgeSec            int64  `json:"age_sec"`
	FirstSeen         string `json:"first_seen"`
	LastSeen          string `json:"last_seen"`
	CaptureIncomplete bool   `json:"capture_incomplete,omitempty"`
	RouteInterface    string `json:"route_interface,omitempty"`
	RouteSrcIP        string `json:"route_src_ip,omitempty"`
	RouteGateway      string `json:"route_gateway,omitempty"`
	RouteTable        string `json:"route_table,omitempty"`
	ECH               bool   `json:"ech,omitempty"`
}

// printSnapshotJSON печатает мета о запуске.
func (c *Capture) printSnapshotJSON() {
	ev := SnapshotEvent{
		Event:   newEvent("snapshot"),
		Cycle:   c.printCycle,
		Iface:   c.iface,
		Filter:  c.filter,
		Snaplen: c.snaplen,
		Version: diggerVersion(),
		Uptime:  int64(time.Since(c.stats.StartedAt).Seconds()),
	}
	printJSON(ev)
}

// printHealthJSON печатает Capture Health.
func (c *Capture) printHealthJSON() {
	c.stats.mu.Lock()
	s := c.stats
	c.stats.mu.Unlock()

	quality := "complete"
	if s.PacketsTruncated > 0 || s.DecodeErrors > 0 {
		quality = "incomplete"
	}

	ev := HealthEvent{
		Event:            newEvent("health"),
		Cycle:            c.printCycle,
		Iface:            c.iface,
		Filter:           c.filter,
		Snaplen:          c.snaplen,
		UptimeSec:        int64(time.Since(s.StartedAt).Seconds()),
		PacketsReceived:  s.PacketsReceived,
		PacketsProcessed: s.PacketsProcessed,
		PacketsTruncated: s.PacketsTruncated,
		DecodeErrors:     s.DecodeErrors,
		NoIPLayer:        s.NoIPLayer,
		BytesReceived:    s.BytesReceived,
		BytesProcessed:   s.BytesProcessed,
		Quality:          quality,
	}
	printJSON(ev)
}

// printAllJSON — общая точка входа для JSON-режима.
func (c *Capture) printAllJSON() {
	c.printCycle++
	c.printSnapshotJSON()
	c.printHealthJSON()
	c.printFlowsJSON()
	c.printDNSJSON()
	c.printAttributionJSON()
	c.printProxySuspicionsJSON()
	c.printProxyProcessesJSON()
	c.printAnomaliesJSON()
	c.printDNSObservationsJSON()
}

// looksLikeSNI — простая проверка, похоже ли значение на домен, а не на IP.
func looksLikeSNI(s string) bool {
	if s == "" {
		return false
	}
	// IPv4
	if net.ParseIP(s) != nil {
		return false
	}
	// Домен должен содержать точку
	return strings.Contains(s, ".")
}

// printFlowsJSON печатает агрегированные потоки.
func (c *Capture) printFlowsJSON() {
	flows := c.flows.Aggregate()

	c.stats.mu.Lock()
	incomplete := c.stats.PacketsTruncated > 0 || c.stats.DecodeErrors > 0
	c.stats.mu.Unlock()

	now := time.Now()

	for _, g := range flows {
		// Определяем настоящий SNI: в AggregatedFlow.Label лежит SNI/hostname/IP
		// Если это IP или hostname, SNI пустой
		sni := ""
		label := g.Label

		if looksLikeSNI(g.Label) {
			sni = g.Label
		}

		ev := FlowEvent{
			Event:             newEvent("flow"),
			Cycle:             c.printCycle,
			Label:             label,
			Process:           g.Process,
			SNI:               sni,
			Classification:    g.Class.String(),
			Proto:             g.Proto,
			Recon:             g.Recon.String(),
			Conns:             g.Connections,
			PacketsOut:        g.PacketsOut,
			BytesOut:          g.BytesOut,
			PacketsIn:         g.PacketsIn,
			BytesIn:           g.BytesIn,
			Retransmits:       g.Retransmits,
			Gaps:              g.Gaps,
			AgeSec:            int64(now.Sub(g.FirstSeen).Seconds()),
			FirstSeen:         g.FirstSeen.UTC().Format(time.RFC3339Nano),
			LastSeen:          g.LastSeen.UTC().Format(time.RFC3339Nano),
			CaptureIncomplete: incomplete,
			RouteInterface:    g.Route.Interface,
			RouteSrcIP:        g.Route.SrcIP,
			RouteGateway:      g.Route.Gateway,
			RouteTable:        g.Route.Table,
			ECH:               g.ECH,
		}
		printJSON(ev)
	}
}

// DNSEvent — один DNS-запрос.
type DNSEvent struct {
	Event

	Cycle     int    `json:"cycle"`
	Name      string `json:"name"`
	QType     string `json:"qtype"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Transport string `json:"transport"`
	Count     uint64 `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Flags     string `json:"flags,omitempty"`
}

// DNSObservationEvent — одно наблюдение DNS-ответа с TTL.
type DNSObservationEvent struct {
	Event

	Cycle      int    `json:"cycle"`
	QName      string `json:"qname"`
	IP         string `json:"ip"`
	TTL        uint32 `json:"ttl,omitempty"`
	ObservedAt string `json:"observed_at"`
	ExpiresAt  string `json:"expires_at"`
	ClientIP   string `json:"client_ip,omitempty"`
	ResolverIP string `json:"resolver_ip,omitempty"`
	Transport  string `json:"transport,omitempty"`
}

// printDNSObservationsJSON печатает наблюдения DNS с TTL.
func (c *Capture) printDNSObservationsJSON() {
	var obs []DNSObservation
	if c.dnsAge > 0 {
		cutoff := time.Now().Add(-c.dnsAge)
		obs = c.dnsMapping.SnapshotObservationsSince(cutoff)
	} else {
		obs = c.dnsMapping.SnapshotObservations()
	}

	for _, o := range obs {
		for _, ip := range o.Answers {
			ev := DNSObservationEvent{
				Event:      newEvent("dns_observation"),
				Cycle:      c.printCycle,
				QName:      o.QName,
				IP:         ip,
				TTL:        o.TTL,
				ObservedAt: o.ObservedAt.UTC().Format(time.RFC3339Nano),
				ExpiresAt:  o.ExpiresAt.UTC().Format(time.RFC3339Nano),
				ClientIP:   o.ClientIP,
				ResolverIP: o.ResolverIP,
				Transport:  o.Transport,
			}
			printJSON(ev)
		}
	}
}

// printDNSJSON печатает DNS-запросы.
func (c *Capture) printDNSJSON() {
	queries := c.dnsTable.Snapshot()
	for _, q := range queries {
		// Пропускаем PTR, если showPTR = false
		if !c.showPTR && strings.HasSuffix(q.Name, ".in-addr.arpa") {
			continue
		}
		ev := DNSEvent{
			Event:     newEvent("dns"),
			Cycle:     c.printCycle,
			Name:      q.Name,
			QType:     q.QType,
			SrcIP:     q.SrcIP,
			DstIP:     q.DstIP,
			Transport: q.Transport,
			Count:     q.Count,
			FirstSeen: q.FirstSeen.UTC().Format(time.RFC3339Nano),
			LastSeen:  q.LastSeen.UTC().Format(time.RFC3339Nano),
			Flags:     q.Flags,
		}
		printJSON(ev)
	}
}

// AttributionEvent — одна связка DNS ↔ SNI ↔ IP.
type AttributionEvent struct {
	Event

	Cycle      int      `json:"cycle"`
	Local      string   `json:"local"`
	RemoteIP   string   `json:"remote_ip"`
	RemotePort uint16   `json:"remote_port"`
	SNI        string   `json:"sni,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	Status     string   `json:"status"` // "✓", "~", "?", "✗", "⚠"
	Reason     string   `json:"reason,omitempty"`
	AgeSec     int64    `json:"age_sec"`
}

// printAttributionJSON печатает связки DNS ↔ SNI ↔ IP.
func (c *Capture) printAttributionJSON() {
	attrs := BuildAttributions(c.flows.Snapshot(), c.dnsMapping)
	for _, a := range attrs {
		// Определяем статус и причину
		status := "?"
		reason := ""

		switch {
		case a.Matched:
			status = "✓"
			reason = "sni matches dns"
		case a.Mismatch:
			status = "⚠"
			reason = "sni != dns"
		case len(a.DNSNames) > 0:
			status = "~"
			reason = "dns only, no sni"
		case a.SNI != "":
			status = "✗"
			reason = "sni only, no dns"
		default:
			status = "?"
			reason = "no sni, no dns"
		}

		ev := AttributionEvent{
			Event:      newEvent("attribution"),
			Cycle:      c.printCycle,
			Local:      fmt.Sprintf("%s:%d", a.LocalIP, a.LocalPort),
			RemoteIP:   a.RemoteIP,
			RemotePort: a.RemotePort,
			SNI:        a.SNI,
			DNSNames:   a.DNSNames,
			Status:     status,
			Reason:     reason,
			AgeSec:     int64(a.Age.Seconds()),
		}
		printJSON(ev)
	}
}

// ProxySuspicionEvent — поток, похожий на прокси.
type ProxySuspicionEvent struct {
	Event

	Cycle      int    `json:"cycle"`
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	SNI        string `json:"sni,omitempty"`
	Process    string `json:"process,omitempty"`
	Reason     string `json:"reason"`
	Confidence string `json:"confidence"`
	AgeSec     int64  `json:"age_sec"`
}

// printProxySuspicionsJSON печатает подозрения на прокси.
func (c *Capture) printProxySuspicionsJSON() {
	sus := BuildProxySuspicions(c.flows.Snapshot(), c.dnsMapping)
	for _, s := range sus {
		conf := "heuristic"
		switch {
		case strings.Contains(s.Reason, "процесс-прокси"):
			conf = "process"
		case strings.Contains(s.Reason, "прокси-фронт"):
			conf = "dns-mismatch"
		}

		ev := ProxySuspicionEvent{
			Event:      newEvent("proxy_suspicion"),
			Cycle:      c.printCycle,
			Local:      fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort),
			Remote:     fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort),
			SNI:        s.SNI,
			Process:    s.Process,
			Reason:     s.Reason,
			Confidence: conf,
			AgeSec:     int64(s.Age.Seconds()),
		}
		printJSON(ev)
	}
}

// ProxyProcessEvent — агрегат по процессу-прокси.
type ProxyProcessEvent struct {
	Event

	Cycle     int    `json:"cycle"`
	Process   string `json:"process"`
	Conns     int    `json:"conns"`
	BytesOut  uint64 `json:"bytes_out"`
	BytesIn   uint64 `json:"bytes_in"`
	RemoteIPs int    `json:"remote_ips"`
	AgeSec    int64  `json:"age_sec"`
}

// printProxyProcessesJSON печатает агрегат по процессам-прокси.
func (c *Capture) printProxyProcessesJSON() {
	procs := BuildProxyProcesses(c.flows.Snapshot())
	now := time.Now()
	for _, p := range procs {
		ev := ProxyProcessEvent{
			Event:     newEvent("proxy_process"),
			Cycle:     c.printCycle,
			Process:   p.Process,
			Conns:     p.Conns,
			BytesOut:  p.BytesOut,
			BytesIn:   p.BytesIn,
			RemoteIPs: p.RemoteIPs,
			AgeSec:    int64(now.Sub(p.FirstSeen).Seconds()),
		}
		printJSON(ev)
	}
}

// AnomalyEvent — аномалия (⚡NEW, ⚠HASH, ⚠BEACON, ⚠PROXY, ⚠DNS-LEAK).
type AnomalyEvent struct {
	Event

	Cycle   int    `json:"cycle"`
	Kind    string `json:"kind"` // NEW, HASH, BEACON, PROXY, DNS-LEAK
	Domain  string `json:"domain,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Process string `json:"process,omitempty"`
	AgeSec  int64  `json:"age_sec"`
}

// printAnomaliesJSON печатает аномалии.
func (c *Capture) printAnomaliesJSON() {
	if c.anomaly == nil {
		return
	}

	records := c.anomaly.CollectAnomalies(5 * time.Minute)
	now := time.Now()

	for _, a := range records {
		ev := AnomalyEvent{
			Event:   newEvent("anomaly"),
			Cycle:   c.printCycle,
			Kind:    a.Kind,
			Domain:  a.Domain,
			Detail:  a.Detail,
			Process: a.Process,
			AgeSec:  int64(now.Sub(a.Time).Seconds()),
		}
		printJSON(ev)
	}
}
