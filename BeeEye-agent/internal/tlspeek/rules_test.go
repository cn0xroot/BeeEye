package tlspeek

import "testing"

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
