package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SchemaVersion — версия схемы baseline.
const SchemaVersion = 2

// Baseline — снимок нормального поведения.
type Baseline struct {
	Schema    int               `json:"schema"`
	Created   time.Time         `json:"created"`
	Iface     string            `json:"iface"`
	Domains   []string          `json:"domains"`
	Processes []string          `json:"processes"`
	Devices   []string          `json:"devices"`
	JA3       map[string]string `json:"ja3,omitempty"`
	JA4       map[string]string `json:"ja4,omitempty"`
}

// Save записывает baseline в файл.
func Save(path string, b *Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Load читает baseline из файла.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if b.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported schema: %d (expected %d)", b.Schema, SchemaVersion)
	}
	return &b, nil
}
