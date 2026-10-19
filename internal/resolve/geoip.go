package resolve

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// Geo looks addresses up in MaxMind GeoLite2/GeoIP2 .mmdb files.
type Geo struct {
	country, city, asn *maxminddb.Reader
}

// GeoInfo is the result of a lookup.
type GeoInfo struct {
	Country string // ISO code
	City    string
	ASN     uint
	Org     string
}

var (
	geoMu sync.RWMutex
	geo   *Geo
)

// LoadGeoIP opens the databases found in dir (GeoLite2-Country.mmdb,
// GeoLite2-City.mmdb, GeoLite2-ASN.mmdb and their GeoIP2 counterparts).
// It returns the names of the files that were loaded.
func LoadGeoIP(dir string) []string {
	geoMu.Lock()
	defer geoMu.Unlock()
	geo = nil
	if dir == "" {
		return nil
	}
	g := &Geo{}
	var loaded []string
	open := func(names ...string) *maxminddb.Reader {
		for _, n := range names {
			p := filepath.Join(dir, n)
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if r, err := maxminddb.Open(p); err == nil {
				loaded = append(loaded, n)
				return r
			}
		}
		return nil
	}
	g.country = open("GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb")
	g.city = open("GeoLite2-City.mmdb", "GeoIP2-City.mmdb")
	g.asn = open("GeoLite2-ASN.mmdb", "GeoIP2-ISP.mmdb")
	if g.country == nil && g.city == nil && g.asn == nil {
		return nil
	}
	geo = g
	return loaded
}

// GeoAvailable reports whether a database is loaded.
func GeoAvailable() bool {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return geo != nil
}

type geoCityRec struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISO string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type geoASNRec struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// GeoLookup returns what the loaded databases know about ip.
func GeoLookup(ip netip.Addr) (GeoInfo, bool) {
	geoMu.RLock()
	defer geoMu.RUnlock()
	if geo == nil || !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return GeoInfo{}, false
	}
	var out GeoInfo
	found := false
	for _, r := range []*maxminddb.Reader{geo.city, geo.country} {
		if r == nil || out.Country != "" {
			continue
		}
		var rec geoCityRec
		if res := r.Lookup(ip); res.Found() && res.Decode(&rec) == nil {
			out.Country = rec.Country.ISO
			out.City = rec.City.Names["en"]
			found = found || out.Country != ""
		}
	}
	if geo.asn != nil {
		var rec geoASNRec
		if res := geo.asn.Lookup(ip); res.Found() && res.Decode(&rec) == nil {
			out.ASN, out.Org = rec.Number, strings.TrimSpace(rec.Org)
			found = found || out.ASN != 0
		}
	}
	return out, found
}
