package policy

// Policy — правила ожидаемого сетевого поведения.
type Policy struct {
	// Разрешённые DNS-резолверы.
	// Если список не пуст — любой DNS-запрос к IP вне списка → violation.
	DNSResolvers []string `yaml:"dns_resolvers"`

	// AllowDirect — домены, которым разрешён прямой outbound (не через прокси).
	AllowDirect []string `yaml:"allow_direct"`

	// IPv6 — разрешён ли IPv6-трафик.
	// nil = не проверять, false = запрещён, true = разрешён.
	IPv6 *bool `yaml:"ipv6,omitempty"`
}

// Violation — нарушение политики.
type Violation struct {
	Rule     string // "dns_resolver", "direct_outbound", "ipv6"
	Expected string
	Actual   string
	Detail   string
}
