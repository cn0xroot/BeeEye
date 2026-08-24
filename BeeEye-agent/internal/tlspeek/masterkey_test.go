//go:build linux

package tlspeek

import (
	"encoding/hex"
	"testing"
	"unsafe"
)

func TestMasterKeyOffsetsLookup(t *testing.T) {
	cases := []struct {
		version string
		wantOK  bool
	}{
		{"OpenSSL 3.0.13", true},
		{"OpenSSL 3.0.16", true},
		{"OpenSSL 3.0.99", true}, // same minor branch, same measured row
		{"OpenSSL 3.1.0", false}, // different minor branch, not measured
		{"OpenSSL 1.1.1w", false},
		{"GnuTLS 3.8.3", false},
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		_, ok := masterKeyOffsets(c.version)
		if ok != c.wantOK {
			t.Errorf("masterKeyOffsets(%q) ok=%v, want %v", c.version, ok, c.wantOK)
		}
	}
}

// TestSSLOffsetsSizeMatchesBPFStruct guards the same class of bug
// TestTLSEventLayoutMatchesBTF catches for the event struct: SSLOffsets is
// marshaled into the ssl_offsets BPF map by raw memory layout (cilium/ebpf),
// so it must stay exactly 4 packed uint32s — 16 bytes, matching struct
// BeeEye_ssl_offsets in bpf/BeeEye_tls_events.h field-for-field.
func TestSSLOffsetsSizeMatchesBPFStruct(t *testing.T) {
	var o SSLOffsets
	if got, want := unsafe.Sizeof(o), uintptr(16); got != want {
		t.Fatalf("sizeof(SSLOffsets) = %d, want %d (keep it 4 packed uint32 fields, matching struct BeeEye_ssl_offsets)", got, want)
	}
}

func TestKeylogLine(t *testing.T) {
	data := make([]byte, 88)
	clientRandom := make([]byte, 32)
	masterKey := make([]byte, 48)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	for i := range masterKey {
		masterKey[i] = byte(0x80 + i)
	}
	copy(data[0:32], clientRandom)
	data[32] = 48 // master_key_length, little-endian u64
	copy(data[40:88], masterKey)

	ev := &Event{Dir: DirKeylog, Data: data}
	line, ok := ev.KeylogLine()
	if !ok {
		t.Fatal("want ok")
	}
	want := "CLIENT_RANDOM " + hex.EncodeToString(clientRandom) + " " + hex.EncodeToString(masterKey)
	if line != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
}

func TestKeylogLineRejectsWrongDirection(t *testing.T) {
	ev := &Event{Dir: DirWrite, Data: make([]byte, 88)}
	if _, ok := ev.KeylogLine(); ok {
		t.Fatal("want ok=false for a non-keylog direction")
	}
}

func TestKeylogLineRejectsWrongLength(t *testing.T) {
	data := make([]byte, 88)
	data[32] = 32 // claims a 32-byte secret, not the fixed TLS1.2 48
	ev := &Event{Dir: DirKeylog, Data: data}
	if _, ok := ev.KeylogLine(); ok {
		t.Fatal("want ok=false when master_key_length != 48")
	}
}

func TestAttachMasterKeyIgnoresNonOpenSSL(t *testing.T) {
	// AttachMasterKey must be a safe no-op for any family/version this
	// table has no row for, and must never panic on an unloaded Peeker
	// state — exercised here by simply not crashing with pids that would
	// otherwise trigger a nil p.coll dereference if the early return were
	// missing.
	p := &Peeker{}
	p.AttachMasterKey("GnuTLS", "GnuTLS 3.8.3", []int{1, 2, 3})
	p.AttachMasterKey("OpenSSL", "OpenSSL 1.1.1w", []int{1})
	p.AttachMasterKey("OpenSSL", "", nil)
}
