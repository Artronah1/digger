package capture

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/geoip2-golang/v2"
)

var (
	geoipOnce sync.Once
	geoipDB   *geoip2.Reader
	geoipErr  error
)

// geoipDBPath: $DIGGER_GEOIP_DB → ~/.digger/… → CWD (прошлый вариант
// зависел только от CWD).
func geoipDBPath() string {
	if p := os.Getenv("DIGGER_GEOIP_DB"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		p := filepath.Join(home, ".digger", "GeoLite2-Country.mmdb")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "GeoLite2-Country.mmdb"
}

func initGeoIP() error {
	geoipOnce.Do(func() {
		geoipDB, geoipErr = geoip2.Open(geoipDBPath())
	})
	return geoipErr
}

// geoipCountry возвращает ISO-код страны или "" — «неизвестно»
// (нет БД, ошибки распознавания). Различать «неизвестно» и «не RU»
// критично: без БД все IP считались не-российскими и ложно флагались.
func geoipCountry(ip string) string {
	if err := initGeoIP(); err != nil || geoipDB == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	record, err := geoipDB.Country(addr)
	if err != nil || !record.HasData() {
		return ""
	}
	return record.Country.ISOCode
}

func isLikelyRussianIP(ip string) bool {
	return geoipCountry(ip) == "RU"
}

// CloseGeoIP освобождает базу. Вызывать ТОЛЬКО после остановки захвата —
// конкурентный lookup по закрытому Reader — гонка.
func CloseGeoIP() {
	if geoipDB != nil {
		geoipDB.Close()
		geoipDB = nil
	}
}
