package resolve

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func writeDB(t *testing.T, path, typ string, recs map[string]mmdbtype.Map) {
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: typ, RecordSize: 24})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, rec := range recs {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.Create(path)
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}

func TestGeoIP(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, filepath.Join(dir, "GeoLite2-City.mmdb"), "GeoLite2-City", map[string]mmdbtype.Map{
		"8.8.8.0/24": {"country": mmdbtype.Map{"iso_code": mmdbtype.String("US")}, "city": mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Mountain View")}}},
	})
	writeDB(t, filepath.Join(dir, "GeoLite2-ASN.mmdb"), "GeoLite2-ASN", map[string]mmdbtype.Map{
		"8.8.8.0/24": {"autonomous_system_number": mmdbtype.Uint32(15169), "autonomous_system_organization": mmdbtype.String("GOOGLE")},
	})
	defer LoadGeoIP("")
	if got := LoadGeoIP(dir); len(got) != 2 {
		t.Fatalf("loaded %v", got)
	}
	info, ok := GeoLookup(netip.MustParseAddr("8.8.8.8"))
	if !ok || info.Country != "US" || info.City != "Mountain View" || info.ASN != 15169 || info.Org != "GOOGLE" {
		t.Errorf("%+v %v", info, ok)
	}
	if _, ok := GeoLookup(netip.MustParseAddr("10.1.2.3")); ok {
		t.Error("private address resolved")
	}
	if _, ok := GeoLookup(netip.MustParseAddr("9.9.9.9")); ok {
		t.Error("unknown address resolved")
	}
}
