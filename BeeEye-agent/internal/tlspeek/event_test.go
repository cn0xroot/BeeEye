//go:build linux

package tlspeek

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// TestTLSEventLayoutMatchesBTF is the guard on this program's kernel↔userspace
// contract, and works the same way internal/ebpf's does: ParseEvent reads at
// hardcoded offsets, so the offsets are checked against the layout the
// compiler actually produced rather than against a comment. Reordering a field
// in BeeEye_tls_events.h must fail the build, not quietly shift every captured
// byte by four.
func TestTLSEventLayoutMatchesBTF(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		t.Fatalf("load embedded object: %v", err)
	}
	var st *btf.Struct
	if err := spec.Types.TypeByName("BeeEye_tls_event", &st); err != nil {
		t.Fatalf("struct BeeEye_tls_event not found in BTF: %v", err)
	}
	if got := int(st.Size); got != EventSize {
		t.Errorf("struct size: C says %d, Go EventSize is %d", got, EventSize)
	}

	want := map[string]uint32{
		"ts_ns": offTS, "pid": offPID, "tid": offTID,
		"len": offLen, "orig_len": offOrigLen, "dir": offDir,
		"comm": offComm, "data": offData,
	}
	got := map[string]uint32{}
	for _, m := range st.Members {
		got[m.Name] = uint32(m.Offset.Bytes())
	}
	for name, off := range want {
		actual, ok := got[name]
		if !ok {
			t.Errorf("field %q missing from struct BeeEye_tls_event", name)
			continue
		}
		if actual != off {
			t.Errorf("field %q: C offset %d, Go reads at %d", name, actual, off)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok && name != "_pad" {
			t.Errorf("field %q exists in C but Go does not decode it", name)
		}
	}
}

// TestParseEventRejectsImplausibleLength covers the case that matters most if
// the contract ever does drift: a length field read at the wrong offset would
// otherwise index far past the record.
func TestParseEventRejectsImplausibleLength(t *testing.T) {
	rec := make([]byte, EventSize)
	binary.LittleEndian.PutUint32(rec[offLen:], uint32(ChunkCap+1))
	if _, err := ParseEvent(rec); err == nil {
		t.Fatal("a length past ChunkCap must be rejected, not trusted")
	}

	// A short record must not panic either.
	if _, err := ParseEvent(make([]byte, 8)); err == nil {
		t.Fatal("a short record must be rejected")
	}
}

// TestParseEventRoundTrip builds a record the way the kernel would and checks
// every field survives, including the truncation flag.
func TestParseEventRoundTrip(t *testing.T) {
	rec := make([]byte, EventSize)
	binary.LittleEndian.PutUint64(rec[offTS:], 1234567890)
	binary.LittleEndian.PutUint32(rec[offPID:], 4242)
	binary.LittleEndian.PutUint32(rec[offTID:], 4243)
	binary.LittleEndian.PutUint32(rec[offLen:], 5)
	binary.LittleEndian.PutUint32(rec[offOrigLen:], 9000)
	rec[offDir] = byte(DirRead)
	copy(rec[offComm:], "curl\x00")
	copy(rec[offData:], "hello")

	ev, err := ParseEvent(rec)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.PID != 4242 || ev.TID != 4243 {
		t.Errorf("pid/tid = %d/%d, want 4242/4243", ev.PID, ev.TID)
	}
	if ev.Comm != "curl" {
		t.Errorf("comm = %q, want curl", ev.Comm)
	}
	if string(ev.Data) != "hello" {
		t.Errorf("data = %q, want hello", ev.Data)
	}
	if ev.Dir != DirRead || ev.Dir.String() != "read" {
		t.Errorf("dir = %v", ev.Dir)
	}
	if !ev.Truncated() {
		t.Error("orig_len 9000 with 5 bytes captured must report as truncated")
	}

	// The returned slice must not alias the ringbuf sample.
	ev.Data[0] = 'H'
	if rec[offData] != 'h' {
		t.Error("ParseEvent aliased the ringbuf memory instead of copying it")
	}
}
