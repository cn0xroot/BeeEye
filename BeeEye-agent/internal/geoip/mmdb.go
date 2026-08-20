// MaxMind DB (.mmdb) backing for geoip. When a City/Country/ASN database is
// present, lookups return accurate country, province, city and network operator
// (F22). Everything stays local — this reads a file on disk, never an online
// API, as the privacy requirement demands (§3.9).
//
// The databases are not shipped (licensing + size). Load points geoip at
// whatever is available; common locations are auto-discovered. Without any
// database the package falls back to the built-in first-octet table, clearly
// labelled Source="builtin".
package geoip

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/geoip2-golang"

	"BeeEye/internal/model"
)

type mmdb struct {
	mu       sync.RWMutex
	city     *geoip2.Reader // City or Country database
	asn      *geoip2.Reader // ASN database (operator / organization)
	cityHas  bool           // true when the city DB actually carries city/subdivision
	loaded   bool
	cityPath string
	asnPath  string
}

// Status reports what geoip is actually running on, so a caller (the API, a
// setup script) can tell an operator "you have country-only, want city too?"
// instead of silently returning coarse data with no way to know why.
type Status struct {
	Loaded   bool   `json:"loaded"`
	CityPath string `json:"city_path,omitempty"`
	HasCity  bool   `json:"has_city"` // city/subdivision names available
	ASNPath  string `json:"asn_path,omitempty"`
	HasASN   bool   `json:"has_asn"`  // operator/ASN available
	Accuracy string `json:"accuracy"` // "city" | "country" | "builtin"
}

// GetStatus reports the current geoip configuration for display.
func GetStatus() Status {
	db.mu.RLock()
	defer db.mu.RUnlock()
	st := Status{
		Loaded:   db.loaded,
		CityPath: db.cityPath,
		HasCity:  db.city != nil && db.cityHas,
		ASNPath:  db.asnPath,
		HasASN:   db.asn != nil,
	}
	switch {
	case st.HasCity:
		st.Accuracy = "city"
	case db.city != nil:
		st.Accuracy = "country"
	default:
		st.Accuracy = "builtin"
	}
	return st
}

var db mmdb

// candidateCity / candidateASN are where a database is looked for when no
// explicit path is given. Order matters: a real GeoLite2-City beats a
// country-only file, which beats Clash's bundled Country.mmdb.
var candidateCity = []string{
	"data/GeoLite2-City.mmdb", "data/GeoCN.mmdb", "data/GeoLite2-Country.mmdb", "data/Country.mmdb",
	"/usr/share/GeoIP/GeoLite2-City.mmdb", "/usr/share/GeoIP/GeoLite2-Country.mmdb",
	"/var/lib/GeoIP/GeoLite2-City.mmdb",
	// Clash ships a country-only MaxMind DB; a common thing to already have.
	"/usr/lib/Clash Verge/resources/Country.mmdb",
}

// clashHomePaths returns per-user Clash database locations, checked after the
// system ones. Kept in a function because they depend on $HOME.
func clashHomePaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".local/share/io.github.clash-verge-rev.clash-verge-rev/Country.mmdb"),
		filepath.Join(home, ".config/clash/Country.mmdb"),
	}
}

var candidateASN = []string{
	"data/GeoLite2-ASN.mmdb", "data/GeoCN.mmdb",
	"/usr/share/GeoIP/GeoLite2-ASN.mmdb", "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
}

// Load opens geoip databases. cityPath and asnPath override the auto-discovery
// when non-empty. Missing databases are not an error — the package degrades to
// the built-in table. Extra discovery paths (e.g. the Clash Country.mmdb the
// user already has) can be appended by the caller via the arguments.
func Load(cityPath, asnPath string, extra ...string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.loaded = true

	cityCands := candidateCity
	if cityPath != "" {
		cityCands = append([]string{cityPath}, cityCands...)
	}
	cityCands = append(cityCands, extra...)
	cityCands = append(cityCands, clashHomePaths()...)
	if r, path := openFirst(cityCands); r != nil {
		db.city = r
		db.cityPath = path
		md := r.Metadata()
		// City databases have "City" in their type; a country-only file does not.
		db.cityHas = md.DatabaseType != "" && containsFold(md.DatabaseType, "City")
		log.Printf("geoip: loaded %s (%s)", path, md.DatabaseType)
	}

	asnCands := candidateASN
	if asnPath != "" {
		asnCands = append([]string{asnPath}, asnCands...)
	}
	if r, path := openFirst(asnCands); r != nil {
		db.asn = r
		db.asnPath = path
		log.Printf("geoip: loaded ASN database %s", path)
	}

	if db.city == nil && db.asn == nil {
		log.Printf("geoip: no .mmdb database found; using the built-in coarse table. " +
			"Drop GeoLite2-City.mmdb / GeoLite2-ASN.mmdb (or GeoCN.mmdb) into ./data for accurate city/operator.")
	}
}

func openFirst(paths []string) (*geoip2.Reader, string) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		r, err := geoip2.Open(p)
		if err != nil {
			log.Printf("geoip: open %s: %v", p, err)
			continue
		}
		return r, filepath.Clean(p)
	}
	return nil, ""
}

// lookupMMDB fills a GeoInfo from the loaded databases. ok is false when no
// database is loaded, so Lookup can fall back to the built-in table.
func lookupMMDB(ip net.IP) (model.GeoInfo, bool) {
	db.mu.RLock()
	city, asn, cityHas := db.city, db.asn, db.cityHas
	db.mu.RUnlock()
	if city == nil && asn == nil {
		return model.GeoInfo{}, false
	}

	g := model.GeoInfo{IP: ip.String(), Source: "mmdb"}
	if city != nil {
		if rec, err := city.City(ip); err == nil {
			g.Country = rec.Country.IsoCode
			if g.Country == "" {
				g.Country = rec.RegisteredCountry.IsoCode
			}
			g.Lat, g.Lon = rec.Location.Latitude, rec.Location.Longitude
			if cityHas {
				if len(rec.Subdivisions) > 0 {
					g.Region = pickName(rec.Subdivisions[0].Names)
				}
				g.City = pickName(rec.City.Names)
			}
		}
	}
	if asn != nil {
		if rec, err := asn.ASN(ip); err == nil {
			g.ISP = rec.AutonomousSystemOrganization
			g.ASN = rec.AutonomousSystemNumber
		}
	}
	if g.Country == "" {
		g.Country = "??"
	}
	return g, true
}

// pickName prefers Simplified Chinese, then English, then any available name,
// so a zh UI shows 中文 place names when the database carries them.
func pickName(names map[string]string) string {
	for _, k := range []string{"zh-CN", "zh", "en"} {
		if v := names[k]; v != "" {
			return v
		}
	}
	for _, v := range names {
		return v
	}
	return ""
}

func containsFold(s, sub string) bool {
	// small, dependency-free case-insensitive contains
	ls, lsub := []byte(s), []byte(sub)
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	if len(lsub) == 0 {
		return true
	}
	for i := 0; i+len(lsub) <= len(ls); i++ {
		ok := true
		for j := range lsub {
			if lower(ls[i+j]) != lower(lsub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
