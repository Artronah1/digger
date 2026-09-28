package capture

import (
	"net/netip"
	"sync"

	"github.com/oschwald/geoip2-golang/v2"
)

var (
	geoipDB     *geoip2.Reader
	geoipOnce   sync.Once
	geoipErr    error
	geoipDBPath = "/home/Kirill/digger/GeoLite2-Country.mmdb"
)

func initGeoIP() error {
	geoipOnce.Do(func() {
		geoipDB, geoipErr = geoip2.Open(geoipDBPath)
	})
	return geoipErr
}

func isLikelyCountry(ip, countryCode string) bool {
	if err := initGeoIP(); err != nil {
		return false
	}
	if geoipDB == nil {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	record, err := geoipDB.Country(addr)
	if err != nil || !record.HasData() {
		return false
	}

	return record.Country.ISOCode == countryCode
}

func isLikelyRussianIP(ip string) bool {
	return isLikelyCountry(ip, "RU")
}

func CloseGeoIP() {
	if geoipDB != nil {
		geoipDB.Close()
	}
}
