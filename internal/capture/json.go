package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
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
	Iface   string `json:"iface"`
	Filter  string `json:"filter"`
	Snaplen int    `json:"snaplen"`
	Version string `json:"version"`
	Uptime  int64  `json:"uptime_sec"`
}

// HealthEvent — счётчики Capture Health.
type HealthEvent struct {
	Event
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

// printSnapshotJSON печатает мета о запуске.
func (c *Capture) printSnapshotJSON() {
	ev := SnapshotEvent{
		Event:   newEvent("snapshot"),
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
// Пока печатает только snapshot и health.
// Дальше добавим flow, dns, attribution, proxy_suspicion, anomaly.
func (c *Capture) printAllJSON() {
	c.printSnapshotJSON()
	c.printHealthJSON()
}
