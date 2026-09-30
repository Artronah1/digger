package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"digger/internal/baseline"
)

// schemaVersion — версия схемы JSON. При breaking changes — увеличивать.
//
// История:
//
//	1 — исходная схема (v0.3.0–v0.6.0)
//	2 — v0.7.0: attribution.status коды вместо глифов,
//	    FlowEvent без RemoteIP/RemotePort,
//	    ProxySuspicion.ReasonCode, cycle в событиях
const schemaVersion = 2

func diggerVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

// --- Общие хелперы ---

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

// fmtTime — единый формат времени в событиях.
func fmtTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// stripReconNote убирает суффикс " ⚠gap"/" ⚠partial", который Aggregate
// добавляет к Label ради текстового вывода. В JSON recon идёт отдельным
// полем, а суффикс иначе уезжает и в label.
func stripReconNote(label string) string {
	for _, note := range []string{" ⚠gap", " ⚠partial"} {
		label = strings.TrimSuffix(label, note)
	}
	return label
}

// --- Точка входа ---

// printAllJSON — общая точка входа для JSON-режима.
// Снимок flows берётся ОДИН раз на цикл: раньше Snapshot() копировался
// пять раз, и события одного цикла снимались в разные моменты времени.
// Номер цикла (printCycle) инкрементируется в printAll — см. capture.go.
func (c *Capture) printAllJSON() {
	flows := c.flows.Snapshot()

	c.printMetaJSON()
	c.printHealthJSON()
	c.printFlowsJSON(flows)
	c.printDNSJSON()
	c.printAttributionJSON(flows)
	c.printProxySuspicionsJSON(flows)
	c.printProxyProcessesJSON(flows)
	c.printAnomaliesJSON()
	c.printDNSObservationsJSON()
	c.printDeviceGroupsJSON(flows)
	c.printDevicesJSON(flows)
	c.checkDirectOutbound()
	c.printPolicyViolationsJSON()
}

// --- Метаданные и health ---

// SnapshotEvent — метаданные запуска (kind "snapshot" оставлен
// для совместимости схемы).
type SnapshotEvent struct {
	Event
	Cycle   int    `json:"cycle"`
	Iface   string `json:"iface"`
	Filter  string `json:"filter"`
	Snaplen int    `json:"snaplen"`
	Version string `json:"version"`
	Uptime  int64  `json:"uptime_sec"`
}

// printMetaJSON — метаданные в начале цикла.
func (c *Capture) printMetaJSON() {
	printJSON(SnapshotEvent{
		Event:   newEvent("snapshot"),
		Cycle:   c.printCycle,
		Iface:   c.iface,
		Filter:  c.filter,
		Snaplen: c.snaplen,
		Version: diggerVersion(),
		Uptime:  int64(time.Since(c.statsSnapshot().StartedAt).Seconds()),
	})
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
	ShortPackets     uint64 `json:"short_packets"`
	BytesReceived    uint64 `json:"bytes_received"`
	BytesProcessed   uint64 `json:"bytes_processed"`
	Quality          string `json:"quality"`
}

// printHealthJSON — статистика захвата.
func (c *Capture) printHealthJSON() {
	s := c.statsSnapshot()

	quality := "complete"
	if s.PacketsTruncated > 0 || s.DecodeErrors > 0 {
		quality = "incomplete"
	}

	printJSON(HealthEvent{
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
		ShortPackets:     s.ShortPackets,
		BytesReceived:    s.BytesReceived,
		BytesProcessed:   s.BytesProcessed,
		Quality:          quality,
	})
}

// --- Baseline ---

// BaselineDiffEvent — различие с baseline.
type BaselineDiffEvent struct {
	Event
	Cycle    int    `json:"cycle"`
	Kind     string `json:"diff_kind"`
	Value    string `json:"value"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// printBaselineDiffJSON печатает различия с baseline.
func (c *Capture) printBaselineDiffJSON(old *baseline.Baseline) {
	diff := baseline.Compare(old, c.BuildBaseline())

	printDiffs := func(kind string, values []string) {
		for _, v := range values {
			printJSON(BaselineDiffEvent{
				Event: newEvent("baseline_diff"),
				Cycle: c.printCycle,
				Kind:  kind,
				Value: v,
			})
		}
	}

	printDiffs("new_domain", diff.NewDomains)
	printDiffs("removed_domain", diff.RemovedDomains)
	printDiffs("new_process", diff.NewProcesses)
	printDiffs("removed_process", diff.RemovedProcesses)
	printDiffs("new_device", diff.NewDevices)
	printDiffs("removed_device", diff.RemovedDevices)
	printDiffs("new_ja3", diff.NewJA3)
	printDiffs("new_ja4", diff.NewJA4)
	printDiffs("changed_ja3", diff.ChangedJA3)
	printDiffs("changed_ja4", diff.ChangedJA4)
}

// --- Потоки ---

// FlowEvent — один агрегированный поток.
type FlowEvent struct {
	Event

	Cycle             int    `json:"cycle"`
	Label             string `json:"label"`
	Process           string `json:"process"`
	SNI               string `json:"sni,omitempty"`
	Hostname          string `json:"hostname,omitempty"`
	Classification    string `json:"classification"`
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
	JA3               string `json:"ja3,omitempty"`
	JA4               string `json:"ja4,omitempty"`
}

// printFlowsJSON печатает агрегированные потоки.
// Настоящие SNI/hostname берутся из полей AggregatedFlow (см. дельту
// flow_table.go) — раньше SNI «угадывали» по Label и путали с hostname
// и суффиксами реконструкции.
func (c *Capture) printFlowsJSON(flows []FlowStats) {
	groups := c.flows.aggregateFrom(flows)

	s := c.statsSnapshot()
	incomplete := s.PacketsTruncated > 0 || s.DecodeErrors > 0
	now := time.Now()

	for _, g := range groups {
		printJSON(FlowEvent{
			Event:             newEvent("flow"),
			Cycle:             c.printCycle,
			Label:             stripReconNote(g.Label),
			Process:           g.Process,
			SNI:               g.SNI,
			Hostname:          g.Hostname,
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
			FirstSeen:         fmtTime(g.FirstSeen),
			LastSeen:          fmtTime(g.LastSeen),
			CaptureIncomplete: incomplete,
			RouteInterface:    g.Route.Interface,
			RouteSrcIP:        g.Route.SrcIP,
			RouteGateway:      g.Route.Gateway,
			RouteTable:        g.Route.Table,
			ECH:               g.ECH,
			JA3:               g.JA3,
			JA4:               g.JA4,
		})
	}
}

// --- DNS ---

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

// printDNSJSON печатает DNS-запросы.
func (c *Capture) printDNSJSON() {
	for _, q := range c.dnsTable.Snapshot() {
		if !c.showPTR && isReverseDNSName(q.Name) {
			continue
		}
		printJSON(DNSEvent{
			Event:     newEvent("dns"),
			Cycle:     c.printCycle,
			Name:      q.Name,
			QType:     q.QType,
			SrcIP:     q.SrcIP,
			DstIP:     q.DstIP,
			Transport: q.Transport,
			Count:     q.Count,
			FirstSeen: fmtTime(q.FirstSeen),
			LastSeen:  fmtTime(q.LastSeen),
			Flags:     q.Flags,
		})
	}
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
		obs = c.dnsMapping.SnapshotObservationsSince(time.Now().Add(-c.dnsAge))
	} else {
		obs = c.dnsMapping.SnapshotObservations()
	}

	for _, o := range obs {
		for _, ip := range o.Answers {
			printJSON(DNSObservationEvent{
				Event:      newEvent("dns_observation"),
				Cycle:      c.printCycle,
				QName:      o.QName,
				IP:         ip,
				TTL:        o.TTL,
				ObservedAt: fmtTime(o.ObservedAt),
				ExpiresAt:  fmtTime(o.ExpiresAt),
				ClientIP:   o.ClientIP,
				ResolverIP: o.ResolverIP,
				Transport:  o.Transport,
			})
		}
	}
}

// --- Атрибуция ---

// AttributionEvent — одна связка DNS ↔ SNI ↔ IP.
type AttributionEvent struct {
	Event

	Cycle      int      `json:"cycle"`
	Local      string   `json:"local"`
	RemoteIP   string   `json:"remote_ip"`
	RemotePort uint16   `json:"remote_port"`
	SNI        string   `json:"sni,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	Status     string   `json:"status"` // matched | mismatch | dns_only | sni_only | unknown
	Reason     string   `json:"reason,omitempty"`
	AgeSec     int64    `json:"age_sec"`
}

// printAttributionJSON печатает связки DNS ↔ SNI ↔ IP.
func (c *Capture) printAttributionJSON(flows []FlowStats) {
	for _, a := range BuildAttributions(flows, c.dnsMapping) {
		status, reason := "unknown", "no sni, no dns"
		switch {
		case a.Matched:
			status, reason = "matched", "sni matches dns"
		case a.Mismatch:
			status, reason = "mismatch", "sni != dns"
		case len(a.DNSNames) > 0:
			status, reason = "dns_only", "dns only, no sni"
		case a.SNI != "":
			status, reason = "sni_only", "sni only, no dns"
		}

		printJSON(AttributionEvent{
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
		})
	}
}

// --- Прокси ---

// ProxySuspicionEvent — поток, похожий на прокси.
type ProxySuspicionEvent struct {
	Event

	Cycle      int    `json:"cycle"`
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	SNI        string `json:"sni,omitempty"`
	Process    string `json:"process,omitempty"`
	Reason     string `json:"reason"`
	ReasonCode string `json:"reason_code,omitempty"` // машинный код причины
	Confidence string `json:"confidence"`
	AgeSec     int64  `json:"age_sec"`
}

// printProxySuspicionsJSON печатает подозрения на прокси.
// Confidence берётся из машинного кода причины (ReasonCode, см. дельту
// attribution.go) — раньше определялся парсингом русских строк вывода.
func (c *Capture) printProxySuspicionsJSON(flows []FlowStats) {
	for _, s := range BuildProxySuspicions(flows, c.dnsMapping) {
		conf := "heuristic"
		switch s.ReasonCode {
		case "process":
			conf = "process"
		case "sni-not-resolved":
			conf = "dns-mismatch"
		}

		printJSON(ProxySuspicionEvent{
			Event:      newEvent("proxy_suspicion"),
			Cycle:      c.printCycle,
			Local:      fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort),
			Remote:     fmt.Sprintf("%s:%d", s.RemoteIP, s.RemotePort),
			SNI:        s.SNI,
			Process:    s.Process,
			Reason:     s.Reason,
			ReasonCode: s.ReasonCode,
			Confidence: conf,
			AgeSec:     int64(s.Age.Seconds()),
		})
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

func (c *Capture) printProxyProcessesJSON(flows []FlowStats) {
	now := time.Now()
	for _, p := range BuildProxyProcesses(flows) {
		printJSON(ProxyProcessEvent{
			Event:     newEvent("proxy_process"),
			Cycle:     c.printCycle,
			Process:   p.Process,
			Conns:     p.Conns,
			BytesOut:  p.BytesOut,
			BytesIn:   p.BytesIn,
			RemoteIPs: p.RemoteIPs,
			AgeSec:    int64(now.Sub(p.FirstSeen).Seconds()),
		})
	}
}

// --- Приложения / устройства ---

// DeviceGroupEvent — агрегат по устройству/приложению.
type DeviceGroupEvent struct {
	Event

	Cycle    int    `json:"cycle"`
	GroupBy  string `json:"group_by"` // "app" | "device"
	Process  string `json:"process"`
	Display  string `json:"display"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Hostname string `json:"hostname,omitempty"`

	Conns      int      `json:"conns"`
	Domains    int      `json:"domains"`
	TopDomains []string `json:"top_domains,omitempty"`

	Direct  int `json:"direct"`
	Proxy   int `json:"proxy"`
	VPN     int `json:"vpn"`
	Unknown int `json:"unknown"`

	BytesOut  uint64 `json:"bytes_out"`
	BytesIn   uint64 `json:"bytes_in"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// printDeviceGroupsJSON печатает агрегаты по устройству/приложению.
func (c *Capture) printDeviceGroupsJSON(flows []FlowStats) {
	if c.groupBy != "app" && c.groupBy != "device" {
		return
	}

	for _, g := range c.flows.aggregateByAppFrom(flows) {
		printJSON(DeviceGroupEvent{
			Event:      newEvent("device_group"),
			Cycle:      c.printCycle,
			GroupBy:    c.groupBy,
			Process:    g.Process,
			Display:    g.Display,
			IP:         g.IP,
			MAC:        g.MAC,
			Vendor:     g.Vendor,
			Hostname:   g.Hostname,
			Conns:      g.Connections,
			Domains:    g.Domains,
			TopDomains: g.TopDomains,
			Direct:     g.Direct,
			Proxy:      g.Proxy,
			VPN:        g.VPN,
			Unknown:    g.Unknown,
			BytesOut:   g.BytesOut,
			BytesIn:    g.BytesIn,
			FirstSeen:  fmtTime(g.FirstSeen),
			LastSeen:   fmtTime(g.LastSeen),
		})
	}
}

// DeviceEvent — событие об устройстве LAN.
type DeviceEvent struct {
	Event
	Cycle     int    `json:"cycle"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Conns     int    `json:"conns"`
	Domains   int    `json:"domains"`
	BytesOut  uint64 `json:"bytes_out"`
	BytesIn   uint64 `json:"bytes_in"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// printDevicesJSON печатает устройства LAN.
func (c *Capture) printDevicesJSON(flows []FlowStats) {
	if !c.routerMode {
		return
	}

	for _, d := range c.flows.buildDevicesFrom(flows) {
		printJSON(DeviceEvent{
			Event:     newEvent("device"),
			Cycle:     c.printCycle,
			IP:        d.IP,
			MAC:       d.MAC,
			Vendor:    d.Vendor,
			Hostname:  d.Hostname,
			Conns:     d.Conns,
			Domains:   d.Domains,
			BytesOut:  d.BytesOut,
			BytesIn:   d.BytesIn,
			FirstSeen: fmtTime(d.FirstSeen),
			LastSeen:  fmtTime(d.LastSeen),
		})
	}
}

// --- Аномалии ---

// AnomalyEvent — аномалия (NEW, HASH, BEACON, PROXY, DNS-LEAK).
type AnomalyEvent struct {
	Event

	Cycle   int    `json:"cycle"`
	Kind    string `json:"kind"`
	Domain  string `json:"domain,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Process string `json:"process,omitempty"`
	AgeSec  int64  `json:"age_sec"`
}

// printAnomaliesJSON печатает аномалии за окно anomalyWindow.
// ВНИМАНИЕ: сейчас это «состояние» — каждая аномалия повторяется
// каждый цикл, пока живёт в окне (~60 раз за 5 минут). Если потребитель
// ждёт события — нужен emit-once (флаг emittedJSON в детекторе).
func (c *Capture) printAnomaliesJSON() {
	if c.anomaly == nil {
		return
	}

	now := time.Now()
	for _, a := range c.anomaly.CollectAnomalies(anomalyWindow) {
		printJSON(AnomalyEvent{
			Event:   newEvent("anomaly"),
			Cycle:   c.printCycle,
			Kind:    a.Kind,
			Domain:  a.Domain,
			Detail:  a.Detail,
			Process: a.Process,
			AgeSec:  int64(now.Sub(a.Time).Seconds()),
		})
	}
}

// --- Policy ---

// PolicyViolationEvent — нарушение политики.
type PolicyViolationEvent struct {
	Event
	Cycle    int    `json:"cycle"`
	Rule     string `json:"rule"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Detail   string `json:"detail"`
}

// printPolicyViolationsJSON печатает нарушения — каждое ОДИН раз
// (раньше весь накопленный список повторялся в каждом цикле).
func (c *Capture) printPolicyViolationsJSON() {
	c.violationsMu.Lock()
	defer c.violationsMu.Unlock()

	for _, v := range c.violations {
		key := v.Rule + "\x00" + v.Actual
		if c.violationsEmitted == nil {
			c.violationsEmitted = make(map[string]bool)
		}
		if c.violationsEmitted[key] {
			continue
		}
		c.violationsEmitted[key] = true

		printJSON(PolicyViolationEvent{
			Event:    newEvent("policy_violation"),
			Cycle:    c.printCycle,
			Rule:     v.Rule,
			Expected: v.Expected,
			Actual:   v.Actual,
			Detail:   v.Detail,
		})
	}
}
