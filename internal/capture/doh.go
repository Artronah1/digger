package capture

import "strings"

var knownDoH = []string{
	"dns.google",
	"dns.google.com",
	"cloudflare-dns.com",
	"mozilla.cloudflare-dns.com",
	"doh.opendns.com",
	"dns.nextdns.io",
	"public.deepdns.net",
	"doh.cleanbrowsing.org",
	"dns.adguard.com",
	"dns.quad9.net",
	"doh.libredns.gr",
	"doh.dns.sb",
	"doh.dnsforge.net",
}

// IsDoHSNI возвращает true, если SNI принадлежит известному DoH-серверу.
func IsDoHSNI(sni string) bool {
	if sni == "" {
		return false
	}
	s := strings.ToLower(sni)
	for _, d := range knownDoH {
		if s == d || strings.HasSuffix(s, "."+d) {
			return true
		}
	}
	return false
}
