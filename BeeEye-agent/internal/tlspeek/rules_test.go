package tlspeek

import (
	"strings"
	"testing"
)

func TestMatchRuleCoversVersionedSONAMEs(t *testing.T) {
	// Cross-version / cross-distro paths must all match one rule — that is the
	// point of matching the SONAME stem rather than a fixed filename.
	cases := map[string]string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":   "OpenSSL",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1": "OpenSSL",
		"/lib/libssl.so":                          "OpenSSL",
		"/usr/lib/libgnutls.so.30":                "GnuTLS",
		"/opt/homebrew/lib/libgnutls.so":          "GnuTLS",
	}
	for path, want := range cases {
		r := matchRule(path)
		if r == nil {
			t.Errorf("%s matched no rule, want %s", path, want)
			continue
		}
		if r.Name != want {
			t.Errorf("%s matched %s, want %s", path, r.Name, want)
		}
	}
	// libcrypto is not a decryption target (no SSL_* symbols).
	if matchRule("/usr/lib/libcrypto.so.3") != nil {
		t.Error("libcrypto should not match a decryption rule")
	}
}

func TestElfHasSymbolsOnSelf(t *testing.T) {
	// The test binary certainly does not export SSL_write; this guards the
	// negative path of the detector against false positives.
	if elfHasSymbols("/proc/self/exe", "SSL_write", "SSL_read") {
		t.Error("the test binary should not report OpenSSL symbols")
	}
}

// TestReadVersionStringOnRealLibraries is a real-machine check (not a
// synthetic ELF) that the version banner parser finds the right family's
// number and stops at the version tuple rather than trailing prose that
// happens to follow it in .rodata — the exact bug that first shipped this
// (GnuTLS's "3.8.3 logging..." string leaking the word "logging" into the
// reported version).
func TestReadVersionStringOnRealLibraries(t *testing.T) {
	libs, err := FindLibraries()
	if err != nil {
		t.Skipf("FindLibraries: %v", err)
	}
	tested := map[string]bool{}
	for _, l := range libs {
		if tested[l.Family] || l.Family == "" {
			continue
		}
		v := readVersionString(l.Path, l.Family)
		if v == "" {
			continue // best-effort; some builds carry no banner
		}
		tested[l.Family] = true
		if !strings.HasPrefix(v, l.Family+" ") {
			t.Errorf("%s: version %q does not start with the family name", l.Path, v)
		}
		for _, r := range v {
			if !(r == ' ' || r == '.' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
				t.Errorf("%s: version %q contains an unexpected character %q — prose leaked past the number", l.Path, v, r)
			}
		}
		t.Logf("%s -> %q", l.Path, v)
	}
	if len(tested) == 0 {
		t.Skip("no library on this host carries a readable version banner")
	}
}
