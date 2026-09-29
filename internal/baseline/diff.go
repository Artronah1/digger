package baseline

import "fmt"

// Diff — различия между baseline и текущим.
type Diff struct {
	NewDomains       []string
	RemovedDomains   []string
	NewProcesses     []string
	RemovedProcesses []string
	NewDevices       []string
	RemovedDevices   []string
	ChangedJA3       []string
	ChangedJA4       []string
	NewJA3           []string
	NewJA4           []string
}

// IsEmpty — нет различий?
func (d *Diff) IsEmpty() bool {
	return len(d.NewDomains) == 0 &&
		len(d.RemovedDomains) == 0 &&
		len(d.NewProcesses) == 0 &&
		len(d.RemovedProcesses) == 0 &&
		len(d.NewDevices) == 0 &&
		len(d.RemovedDevices) == 0 &&
		len(d.ChangedJA3) == 0 &&
		len(d.ChangedJA4) == 0
}

// Total — общее число различий.
func (d *Diff) Total() int {
	return len(d.NewDomains) + len(d.RemovedDomains) +
		len(d.NewProcesses) + len(d.RemovedProcesses) +
		len(d.NewDevices) + len(d.RemovedDevices) +
		len(d.ChangedJA3) + len(d.ChangedJA4)
}

// Compare сравнивает baseline со свежим снимком.
func Compare(old, current *Baseline) *Diff {
	d := &Diff{}

	d.NewDomains = diffNew(old.Domains, current.Domains)
	d.RemovedDomains = diffNew(current.Domains, old.Domains)
	d.NewProcesses = diffNew(old.Processes, current.Processes)
	d.RemovedProcesses = diffNew(current.Processes, old.Processes)
	d.NewDevices = diffNew(old.Devices, current.Devices)
	d.RemovedDevices = diffNew(current.Devices, old.Devices)

	d.ChangedJA3 = diffMap(old.JA3, current.JA3)
	d.ChangedJA4 = diffMap(old.JA4, current.JA4)

	d.NewJA3 = diffMapNew(old.JA3, current.JA3)
	d.NewJA4 = diffMapNew(old.JA4, current.JA4)

	return d
}

// diffMapNew возвращает "key: new" для ключей, которых не было в old.
func diffMapNew(old, current map[string]string) []string {
	var out []string
	for k, v := range current {
		if _, ok := old[k]; !ok {
			out = append(out, fmt.Sprintf("%s: %s", k, v))
		}
	}
	return out
}

// diffNew возвращает элементы, которые есть в b, но нет в a.
func diffNew(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, x := range b {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

// diffMap возвращает "key: old → new" для ключей, где значение изменилось.
func diffMap(old, current map[string]string) []string {
	var out []string
	for k, newV := range current {
		oldV, ok := old[k]
		if !ok {
			continue
		}
		if oldV != newV {
			out = append(out, fmt.Sprintf("%s: %s → %s", k, oldV, newV))
		}
	}
	return out
}
