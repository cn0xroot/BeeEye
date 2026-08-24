//go:build linux

// TLS 1.2 master-secret extraction (F14 phase two — the "masterkey/keylog
// stage" this package's other files reference and detect.go's own comment
// flags as unbuilt). Writes NSS keylog-format lines
// (https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
// so BeeEye-pcapmerge can embed them as a pcapng Decryption Secrets Block
// (F14 phase two's other half) without needing an app that cooperates with
// SSLKEYLOGFILE — path A gets real secrets, not just plaintext.
//
// # Why this needs per-version offsets and cannot be CO-RE
//
// The uprobe programs everywhere else in this package only ever touch
// function *arguments*, which the platform ABI fixes — that is what lets one
// build serve every OpenSSL release (see BeeEye_tls.bpf.c's header comment).
// A master secret lives *inside* the SSL/SSL_SESSION structs, at an offset
// that is a property of one specific OpenSSL source tree, not the ABI. CO-RE
// solves this for kernel structs via BTF the kernel itself carries; a
// userspace release .so is normally built without BTF (verified: `pahole -C
// ssl_st` on this host's system and conda libssl.so.3 both fail with "failed
// to find '.BTF' ELF section") — so there is nothing for CO-RE to relocate
// against, and the only way to get a real offset is to read it out of the
// exact source tree.
//
// # How the offsets below were actually obtained (not guessed)
//
// For each OpenSSL 3.0.x point release installed on the dev machine that
// built this table (3.0.13 — Ubuntu's libssl3t64, and 3.0.16 — the conda
// build both actually observed in real /proc scans this session), the exact
// upstream tag was cloned, `./Configure linux-x86_64 no-shared` run to
// generate its headers, and a throwaway C program computed real
// `offsetof(struct ssl_st, ...)` / `offsetof(struct ssl_session_st, ...)`
// values against ssl/ssl_local.h — the same technique eCapture's own offset
// tables are built with, just done here for the two point releases this
// host actually has instead of eCapture's full multi-decade version matrix.
// Both releases produced byte-identical offsets, consistent with OpenSSL 3.0
// being an LTS branch that does not break struct layout within a minor
// version — so this table is keyed by "OpenSSL 3.0", not by exact patch
// version. That stability assumption is unverified for other 3.0.x patches
// and for any other branch (1.1.1, 3.1, 3.2, 3.3, 3.4, 3.5, ...); rather than
// guess forward from two data points, this table only ever offers a version
// it was actually measured against — an unlisted version falls back to
// plaintext-only capture, exactly like today, never a wrong-offset read.
//
// Extending coverage to another branch is: clone that tag, ./Configure,
// compile the same offsetof probe, add a row. No eBPF or Go logic changes.
package tlspeek

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/cilium/ebpf"
)

// SSLOffsets are the struct-field byte offsets try_extract_master_secret (in
// BeeEye_tls.bpf.c) needs to read a TLS 1.2 master secret out of an `SSL *`.
// Field-for-field mirror of struct BeeEye_ssl_offsets in
// bpf/BeeEye_tls_events.h — TestMasterKeyOffsetsMatchBTF checks the two
// agree, the same discipline TestTLSEventLayoutMatchesBTF already applies to
// the event struct.
type SSLOffsets struct {
	SessionOff      uint32 // offsetof(struct ssl_st, session)
	ClientRandomOff uint32 // offsetof(struct ssl_st, s3.client_random)
	MasterKeyLenOff uint32 // offsetof(struct ssl_session_st, master_key_length)
	MasterKeyOff    uint32 // offsetof(struct ssl_session_st, master_key)
}

// opensslOffsets is keyed by the "<Family> <major>.<minor>" prefix of the
// version string detect.go's readVersionString reports (e.g. "OpenSSL 3.0"
// from "OpenSSL 3.0.13") — see this file's package doc for how each row was
// obtained and why the key is a minor-version prefix rather than an exact
// point release.
var opensslOffsets = map[string]SSLOffsets{
	"OpenSSL 3.0": {
		SessionOff:      2328,
		ClientRandomOff: 352,
		MasterKeyLenOff: 8,
		MasterKeyOff:    80,
	},
}

// masterKeyOffsets looks up the offset row for a version string like
// "OpenSSL 3.0.13", by its major.minor prefix. ok is false for any version
// (or empty string — a library whose banner could not be read) this table
// was not actually measured against.
func masterKeyOffsets(version string) (SSLOffsets, bool) {
	if version == "" {
		return SSLOffsets{}, false
	}
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return SSLOffsets{}, false
	}
	key := parts[0] + "." + parts[1]
	off, ok := opensslOffsets[key]
	return off, ok
}

// SetMasterKeyOffsets tells the loaded programs that pid is running an
// OpenSSL build this table has real offsets for, so try_extract_master_secret
// attempts extraction for its SSL_write calls. A pid never registered here is
// completely unaffected — it gets exactly today's plaintext-only capture.
func (p *Peeker) SetMasterKeyOffsets(pid uint32, off SSLOffsets) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("tlspeek: peeker is closed")
	}
	m, ok := p.coll.Maps["ssl_offsets"]
	if !ok {
		return errors.New("tlspeek: ssl_offsets map not present in loaded object")
	}
	return m.Update(&pid, &off, ebpf.UpdateAny)
}

// AttachMasterKey is Attach's companion: after successfully attaching
// plaintext capture to an OpenSSL-family library, call this with the same
// library's detected version (tlspeek.LibraryVersion) and the pids currently
// mapping it (from the same Library value FindLibraries returned) to also
// register master-key extraction for those pids. A no-op — not an error —
// when family/version has no measured offset row (see masterKeyOffsets), so
// callers can call it unconditionally after every Attach.
func (p *Peeker) AttachMasterKey(family, version string, pids []int) {
	if family != "OpenSSL" {
		return
	}
	off, ok := masterKeyOffsets(version)
	if !ok {
		return
	}
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		_ = p.SetMasterKeyOffsets(uint32(pid), off)
	}
}

// KeylogLine renders a captured master secret as one standard NSS keylog
// line ("CLIENT_RANDOM <hex client_random> <hex master_secret>", the TLS 1.2
// form — see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format),
// or false if ev is not a TLS_DIR_KEYLOG record.
func (e *Event) KeylogLine() (string, bool) {
	if e.Dir != DirKeylog || len(e.Data) < 88 {
		return "", false
	}
	clientRandom := e.Data[0:32]
	masterKeyLen := binary.LittleEndian.Uint64(e.Data[32:40])
	if masterKeyLen != 48 {
		return "", false
	}
	masterKey := e.Data[40:88]
	return "CLIENT_RANDOM " + hexEncode(clientRandom) + " " + hexEncode(masterKey), true
}

func hexEncode(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdig[c>>4]
		out[i*2+1] = hexdig[c&0xf]
	}
	return string(out)
}
