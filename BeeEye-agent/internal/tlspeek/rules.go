package tlspeek

import "regexp"

// LibraryRule declares how to decrypt one family of TLS library by uprobe.
// Support for a new library is a matter of adding a rule here — no code change
// elsewhere — because the eBPF programs only ever read function arguments,
// which every library in this table passes in the same shape:
//
//	write(session/ssl, buf, len)  — plaintext at the buffer on entry
//	read (session/ssl, buf, len)  — plaintext at the buffer on RETURN
//
// So one pair of generic uprobe programs serves them all; a rule just names the
// SONAME to match and the two symbols to hook.
type LibraryRule struct {
	// Name is the human-facing family name shown in the UI and logs.
	Name string
	// SONAME is the pattern a mapped library path must match. It is matched
	// against the full path, so it should anchor on the file name.
	SONAME *regexp.Regexp
	// WriteSym sends plaintext out; its 2nd arg is the buffer, 3rd the length.
	WriteSym string
	// ReadSym receives plaintext; its 2nd arg is the buffer, and the plaintext
	// is only valid once the call returns (hence a uretprobe).
	ReadSym string
	// Optional indicates a library that is nice-to-have but whose symbols are
	// generic I/O (e.g. NSS PR_Write covers non-TLS too); off unless asked for.
	Optional bool
}

// Rules is the built-in table. Order matters only for display; matching tries
// every rule. Add a row to support another library.
//
//   - OpenSSL / LibreSSL / BoringSSL(dynamic) all export SSL_write/SSL_read.
//   - GnuTLS uses gnutls_record_send/recv with the same argument shape.
//
// NSS (PR_Write/PR_Read) and a statically-linked BoringSSL (stripped symbols,
// e.g. Chrome/Node) are deliberately NOT here: the first hooks non-TLS I/O too,
// and the second has no symbols to hook — both are covered by the
// SSLKEYLOGFILE route instead (scripts/tls-decrypt.sh, TLS-DECRYPT.md).
var Rules = []LibraryRule{
	{
		Name:     "OpenSSL",
		SONAME:   regexp.MustCompile(`/libssl\.so`),
		WriteSym: "SSL_write",
		ReadSym:  "SSL_read",
	},
	{
		Name:     "GnuTLS",
		SONAME:   regexp.MustCompile(`/libgnutls\.so`),
		WriteSym: "gnutls_record_send",
		ReadSym:  "gnutls_record_recv",
	},
}

// matchRule returns the first rule whose SONAME matches the path, or nil.
func matchRule(path string) *LibraryRule {
	for i := range Rules {
		if Rules[i].SONAME.MatchString(path) {
			return &Rules[i]
		}
	}
	return nil
}

// soNamePattern is the union of every rule's SONAME, used to scan /proc maps
// for any supported library in one pass.
var soNamePattern = func() *regexp.Regexp {
	alt := ""
	for i, r := range Rules {
		if i > 0 {
			alt += "|"
		}
		alt += "(?:" + r.SONAME.String() + ")"
	}
	return regexp.MustCompile(alt)
}()

// RuleNames lists the supported library families, for the UI to show what the
// current build can decrypt by uprobe.
func RuleNames() []string {
	out := make([]string, len(Rules))
	for i, r := range Rules {
		out[i] = r.Name
	}
	return out
}
