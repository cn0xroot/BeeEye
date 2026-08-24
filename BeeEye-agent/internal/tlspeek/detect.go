package tlspeek

import (
	"debug/elf"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CryptoLib is one crypto library detected on the host, described enough for an
// operator to see what decryption will and will not cover — and why.
type CryptoLib struct {
	Path       string `json:"path"`
	Family     string `json:"family"`            // matched rule name, or "" if none
	Version    string `json:"version,omitempty"` // e.g. "OpenSSL 3.0.13", read from the library's own banner
	Processes  int    `json:"processes"`         // how many live processes map it
	HasSymbols bool   `json:"has_symbols"`       // the hook symbols are present in the ELF
	Attachable bool   `json:"attachable"`        // a rule matched AND its symbols are present
	Note       string `json:"note,omitempty"`    // why it is / is not attachable
}

// Detect surveys the crypto libraries in use on this host and reports, per
// library, whether uprobe decryption can attach to it. It is the backing for
// the "detect crypto libraries" capability: a maintainer adds a rule to
// rules.go and immediately sees new libraries flip to attachable here, and an
// operator sees at a glance which of their tools are covered.
//
// Statically-linked stripped libraries (Chrome, Node's BoringSSL) show up only
// if some process maps a separate object; when they are baked into the main
// binary they are not listed here at all, which is itself the signal that the
// SSLKEYLOGFILE route is the one to use for them.
func Detect() ([]CryptoLib, error) {
	libs, err := FindLibraries()
	if err != nil {
		return nil, err
	}
	out := make([]CryptoLib, 0, len(libs))
	for _, l := range libs {
		c := CryptoLib{Path: l.Path, Family: l.Family, Processes: len(l.PIDs), Version: readVersionString(l.Path, l.Family)}
		rule := matchRule(l.Path)
		if rule == nil {
			c.Note = "no decryption rule matches this library"
			out = append(out, c)
			continue
		}
		c.HasSymbols = elfHasSymbols(l.Path, rule.WriteSym, rule.ReadSym)
		c.Attachable = c.HasSymbols
		if c.HasSymbols {
			c.Note = "uprobe decryption attaches to " + rule.WriteSym + " / " + rule.ReadSym
		} else {
			c.Note = "symbols stripped or absent; use the SSLKEYLOGFILE route instead"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Attachable != out[j].Attachable {
			return out[i].Attachable // attachable first
		}
		return out[i].Processes > out[j].Processes
	})
	return out, nil
}

// versionMarkers gives, per family, the literal prefix its version string
// starts with inside the compiled library — e.g. OpenSSL embeds the exact
// string printed by `openssl version` (OPENSSL_VERSION_TEXT) verbatim in
// .rodata. This is what tells "OpenSSL 3.0.13" apart from "OpenSSL 1.1.1w"
// without running the library — the same fact a per-version offset table
// (TLS-DECRYPT.md's masterkey/keylog stage) would need to pick the right row.
var versionMarkers = map[string][]byte{
	"OpenSSL": []byte("OpenSSL "),
	"GnuTLS":  []byte("GnuTLS "),
}

// LibraryVersion reports the same version banner Detect()'s CryptoLib.Version
// carries, for a caller (Peeker.AttachMasterKey) that already has a library
// path and family and wants just the version string without re-running a
// full Detect() survey.
func LibraryVersion(path, family string) string {
	return readVersionString(path, family)
}

// readVersionString scans the library's readable data for its embedded
// version banner. Best-effort: a stripped or unusually built library may not
// carry one, in which case the family is still known (from the SONAME) even
// though the exact point release is not.
//
// OpenSSL's own text ("OpenSSL 3.0.13 ...") sometimes lives in libcrypto
// rather than libssl even when the two are separate files (libssl is mostly
// protocol logic; libcrypto is the primitives layer, and OPENSSL_VERSION_TEXT
// is compiled into the latter) — so a miss on the given path also tries the
// libcrypto next to it. GnuTLS keeps the marker but requires a digit right
// after the space, rejecting matches like "GnuTLS error: %s" from its own
// error-string table, which otherwise "wins" by appearing first in the file.
func readVersionString(path, family string) string {
	marker, ok := versionMarkers[family]
	if !ok {
		return ""
	}
	if v := scanForVersion(path, marker); v != "" {
		return v
	}
	if family == "OpenSSL" {
		if alt := siblingLibrary(path, "libssl", "libcrypto"); alt != "" {
			return scanForVersion(alt, marker)
		}
	}
	return ""
}

func scanForVersion(path string, marker []byte) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	// The banner lives early in .rodata on every build encountered so far;
	// capping the scan keeps this cheap even on a multi-hundred-MB library.
	const scanCap = 4 << 20
	buf := make([]byte, scanCap)
	n, _ := f.Read(buf)
	buf = buf[:n]

	for start := 0; ; {
		i := indexOf(buf[start:], marker)
		if i < 0 {
			return ""
		}
		i += start
		vs := i + len(marker)
		if vs < len(buf) && buf[vs] >= '0' && buf[vs] <= '9' {
			// The version number itself: digits and dots only, so a banner like
			// "GnuTLS 3.8.3 logging..." reports as "GnuTLS 3.8.3", not the
			// trailing prose that happened to follow it in .rodata. OpenSSL's
			// release date after the number is dropped for the same reason —
			// it is not part of the version tuple a rule table would key on.
			end := vs
			for end < len(buf) && end < vs+24 && (buf[end] == '.' || (buf[end] >= '0' && buf[end] <= '9')) {
				end++
			}
			return string(marker) + string(buf[vs:end])
		}
		start = i + 1 // this occurrence was not followed by a digit; keep looking
	}
}

// siblingLibrary swaps one library name stem for another in the same
// directory and versioned filename, e.g. .../libssl.so.3 → .../libcrypto.so.3.
func siblingLibrary(path, from, to string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if !strings.HasPrefix(base, from) {
		return ""
	}
	cand := filepath.Join(dir, to+strings.TrimPrefix(base, from))
	if _, err := os.Stat(cand); err != nil {
		return ""
	}
	return cand
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

// elfHasSymbols reports whether the ELF exports the given dynamic symbols. This
// is what tells a stripped static BoringSSL (no SSL_write symbol) apart from a
// normal shared OpenSSL, so the UI can steer the user to the right method.
func elfHasSymbols(path string, want ...string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	ef, err := elf.NewFile(f)
	if err != nil {
		return false
	}
	present := map[string]bool{}
	if syms, err := ef.DynamicSymbols(); err == nil {
		for _, s := range syms {
			present[s.Name] = true
		}
	}
	if syms, err := ef.Symbols(); err == nil {
		for _, s := range syms {
			present[s.Name] = true
		}
	}
	for _, w := range want {
		if !present[w] {
			return false
		}
	}
	return true
}
