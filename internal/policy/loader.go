package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load читает policy.yaml.
func Load(path string) (*Policy, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("не удалось разобрать %s: %w", path, err)
	}

	return &p, nil
}

// IsResolverAllowed проверяет, разрешён ли DNS-резолвер.
// Если список пуст — всё разрешено.
func (p *Policy) IsResolverAllowed(ip string) bool {
	if p == nil || len(p.DNSResolvers) == 0 {
		return true
	}
	for _, allowed := range p.DNSResolvers {
		if allowed == ip {
			return true
		}
	}
	return false
}

// IsDirectAllowed проверяет, разрешён ли прямой outbound для домена.
func (p *Policy) IsDirectAllowed(domain string) bool {
	if p == nil || len(p.AllowDirect) == 0 {
		return true
	}
	for _, allowed := range p.AllowDirect {
		if allowed == domain {
			return true
		}
	}
	return false
}

// IsIPv6Allowed проверяет, разрешён ли IPv6.
// nil = не проверять.
func (p *Policy) IsIPv6Allowed() bool {
	if p == nil || p.IPv6 == nil {
		return true
	}
	return *p.IPv6
}
