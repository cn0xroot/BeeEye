package tlspeek

import (
	"debug/elf"
	"os"
	"sort"
)

// CryptoLib is one crypto library detected on the host, described enough for an
// operator to see what decryption will and will not cover — and why.
type CryptoLib struct {
	Path       string `json:"path"`
	Family     string `json:"family"`         // matched rule name, or "" if none
	Processes  int    `json:"processes"`      // how many live processes map it
	HasSymbols bool   `json:"has_symbols"`    // the hook symbols are present in the ELF
	Attachable bool   `json:"attachable"`     // a rule matched AND its symbols are present
	Note       string `json:"note,omitempty"` // why it is / is not attachable
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
		c := CryptoLib{Path: l.Path, Family: l.Family, Processes: len(l.PIDs)}
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
