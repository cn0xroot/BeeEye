// Optional full IEEE OUI registry backing for identity's vendor lookup (F1
// gap: the built-in ouiTable in identity.go only has ~19 illustrative
// entries). Mirrors geoip's Load/Status pattern exactly (see
// internal/geoip/mmdb.go): a file on disk, loaded once at startup, never a
// per-lookup network call (§3.9 privacy requirement) — without the file,
// identity silently keeps using the built-in table.
package identity

import (
	"bufio"
	"encoding/csv"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ouiDB holds the optional full-registry table, keyed by normalized 6-hex OUI
// prefix (MA-L / 24-bit assignments only — see loadOUICSV's doc comment for
// why MA-M/MA-S are not attempted here).
var ouiDB struct {
	mu      sync.RWMutex
	vendors map[string]string
	path    string
}

// OUIStatus reports what identity's vendor lookup is actually running on, so
// a caller (the API, the setup script) can tell an operator "you're on the
// 19-entry built-in table, want the full registry?" instead of silently
// staying coarse — same honesty convention as geoip.Status.
type OUIStatus struct {
	Loaded  bool   `json:"loaded"`
	Path    string `json:"path,omitempty"`
	Entries int    `json:"entries"`
	Source  string `json:"source"` // "ieee-registry" | "builtin"
}

// GetOUIStatus reports the current vendor-table configuration for display.
func GetOUIStatus() OUIStatus {
	ouiDB.mu.RLock()
	defer ouiDB.mu.RUnlock()
	if len(ouiDB.vendors) > 0 {
		return OUIStatus{Loaded: true, Path: ouiDB.path, Entries: len(ouiDB.vendors), Source: "ieee-registry"}
	}
	return OUIStatus{Loaded: false, Entries: len(ouiTable), Source: "builtin"}
}

// candidateOUIPaths mirrors geoip's candidateCity: where to look when no
// explicit path is given. ./data is this project's established convention
// for optional downloaded databases (see scripts/geoip-setup.sh,
// scripts/fingerprint-setup.sh).
var candidateOUIPaths = []string{"data/oui.csv"}

// LoadOUI opens the IEEE OUI registry CSV at path (or the first candidate
// found when path is empty). A missing file is not an error — the package
// keeps using the built-in ~19-entry table, exactly like geoip.Load without
// an mmdb present.
func LoadOUI(path string) {
	cands := candidateOUIPaths
	if path != "" {
		cands = append([]string{path}, cands...)
	}
	for _, p := range cands {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		vendors, err := loadOUICSV(f)
		f.Close()
		if err != nil {
			log.Printf("identity: parse %s: %v", p, err)
			continue
		}
		ouiDB.mu.Lock()
		ouiDB.vendors = vendors
		ouiDB.path = filepath.Clean(p)
		ouiDB.mu.Unlock()
		log.Printf("identity: loaded %d vendor entries from %s", len(vendors), p)
		return
	}
	log.Printf("identity: no OUI registry found; using the built-in %d-entry table. "+
		"Run ./scripts/fingerprint-setup.sh fetch-oui for the full ~50k-entry IEEE registry.", len(ouiTable))
}

// loadOUICSV parses IEEE's public MA-L registry export
// (https://standards-oui.ieee.org/oui/oui.csv — no account or API key
// required, unlike MaxMind's GeoLite2). Columns: Registry,Assignment,
// Organization Name,Organization Address.
//
// Only "MA-L" rows are used. IEEE also publishes MA-M (28-bit) and MA-S
// (36-bit) registries for vendors who bought a smaller block; correctly
// matching those needs prefix-length-aware lookup (a MAC matches a MA-M
// entry on its first 7 hex digits, not 6), which this package's normalizeOUI
// does not do. Rather than silently mis-key those rows into the 6-hex map
// (which would either collide with an unrelated MA-L vendor or never match),
// they are skipped — MA-L alone is already the large majority of registered
// vendors and a strict improvement over the built-in table.
func loadOUICSV(r io.Reader) (map[string]string, error) {
	cr := csv.NewReader(bufio.NewReader(r))
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, err
	}
	regCol, asgCol, orgCol := -1, -1, -1
	for i, h := range header {
		switch strings.TrimSpace(strings.ToLower(h)) {
		case "registry":
			regCol = i
		case "assignment":
			asgCol = i
		case "organization name":
			orgCol = i
		}
	}
	if regCol < 0 || asgCol < 0 || orgCol < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	out := map[string]string{}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // one malformed row must not abort the whole load
		}
		if regCol >= len(rec) || asgCol >= len(rec) || orgCol >= len(rec) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rec[regCol]), "MA-L") {
			continue
		}
		prefix := strings.ToLower(strings.TrimSpace(rec[asgCol]))
		if len(prefix) != 6 {
			continue
		}
		org := strings.TrimSpace(rec[orgCol])
		if org == "" {
			continue
		}
		out[prefix] = org
	}
	return out, nil
}

// lookupVendor checks the full registry first (when loaded), then the
// built-in table — same tiering as geoip.Lookup's mmdb-then-builtin chain.
// The full registry only carries a vendor name, no category/model guess, so
// a hit here still needs the hostname/fingerprint hints below to refine
// category.
func lookupVendor(prefix string) (vendor string, ok bool) {
	ouiDB.mu.RLock()
	if v, hit := ouiDB.vendors[prefix]; hit {
		ouiDB.mu.RUnlock()
		return v, true
	}
	ouiDB.mu.RUnlock()
	if info, hit := ouiTable[prefix]; hit {
		return info.vendor, true
	}
	return "", false
}
