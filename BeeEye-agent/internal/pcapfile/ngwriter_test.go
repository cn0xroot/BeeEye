package pcapfile

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// TestNgWriterRoundTrip writes two packets and a Decryption Secrets Block,
// then reads the packets back with NgReader (the reader this session's own
// eCapture research established BeeEye already had) and manually parses the
// DSB, since NgReader deliberately treats DSB as just another block type it
// skips (pcapng.go's own doc comment says so) — Wireshark, not BeeEye, is
// the DSB's consumer. This is the round-trip that matters: bytes this
// package writes must be bytes this package (and by construction, any
// pcapng-conformant reader) can parse back correctly.
func TestNgWriterRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	nw, err := NewNgWriter(&buf, LinkEthernet, 65535)
	if err != nil {
		t.Fatalf("NewNgWriter: %v", err)
	}

	ts1 := time.Unix(1700000000, 123000) // exact microsecond, round-trips cleanly
	pkt1 := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	if err := nw.WritePacket(ts1, pkt1, len(pkt1)); err != nil {
		t.Fatalf("WritePacket 1: %v", err)
	}

	ts2 := ts1.Add(5 * time.Millisecond)
	pkt2 := []byte{0x01, 0x02, 0x03} // odd length: exercises the 4-byte pad path
	if err := nw.WritePacket(ts2, pkt2, len(pkt2)+10); err != nil {
		t.Fatalf("WritePacket 2: %v", err)
	}

	keylog := []byte("CLIENT_RANDOM 0011223344556677 aabbccdd\nSERVER_HANDSHAKE_TRAFFIC_SECRET 8899aabb ccddeeff\n")
	if err := nw.WriteSecrets(SecretsTypeTLS, keylog); err != nil {
		t.Fatalf("WriteSecrets: %v", err)
	}
	if err := nw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	data := buf.Bytes()

	// Packets: read back through the real NgReader, exactly as Open would
	// hand it to any other BeeEye caller.
	pr, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p1, err := pr.Next()
	if err != nil {
		t.Fatalf("Next (packet 1): %v", err)
	}
	if !bytes.Equal(p1.Data, pkt1) {
		t.Errorf("packet 1 data = %x, want %x", p1.Data, pkt1)
	}
	// NgReader's ngTimestamp (pcapng.go, pre-existing, unrelated to this
	// writer) reconstructs time via a float64 multiplication, which loses a
	// handful of nanoseconds of precision at real epoch-scale tick counts —
	// sub-microsecond drift here is that reader-side characteristic, not a
	// bug in what this writer encoded, so the round-trip check allows it.
	if d := p1.TS.Sub(ts1); d < -time.Microsecond || d > time.Microsecond {
		t.Errorf("packet 1 ts = %v, want %v (within 1µs)", p1.TS, ts1)
	}
	if p1.LinkType != LinkEthernet {
		t.Errorf("packet 1 LinkType = %d, want %d", p1.LinkType, LinkEthernet)
	}

	p2, err := pr.Next()
	if err != nil {
		t.Fatalf("Next (packet 2): %v", err)
	}
	if !bytes.Equal(p2.Data, pkt2) {
		t.Errorf("packet 2 data = %x, want %x", p2.Data, pkt2)
	}
	if p2.OrigLen != len(pkt2)+10 {
		t.Errorf("packet 2 OrigLen = %d, want %d", p2.OrigLen, len(pkt2)+10)
	}

	// NgReader's default case skips DSB by declared length without
	// misparsing it as a packet — confirm Next() reaches EOF cleanly rather
	// than erroring or returning a bogus third "packet".
	if _, err := pr.Next(); err != io.EOF {
		t.Errorf("Next after the DSB = %v, want io.EOF (DSB must be skipped, not misread as a packet)", err)
	}

	// DSB: parse the block directly, since it's exactly what a real pcapng
	// consumer (Wireshark) would do — find the 0x0A block and decode its body.
	secretsType, secretsData, found := findDSB(t, data)
	if !found {
		t.Fatal("no Decryption Secrets Block found in the written file")
	}
	if secretsType != SecretsTypeTLS {
		t.Errorf("DSB secrets_type = 0x%x, want 0x%x (SecretsTypeTLS)", secretsType, SecretsTypeTLS)
	}
	if !bytes.Equal(secretsData, keylog) {
		t.Errorf("DSB secrets data = %q, want %q", secretsData, keylog)
	}
}

// findDSB scans the raw block stream for a Decryption Secrets Block and
// decodes its Secrets Type + Secrets Data, independent of NgReader (which
// deliberately does not surface DSB contents) — this is a from-scratch
// parse against the pcapng spec's own block framing, the same framing every
// other block in this file uses (type, total length, body, total length).
func findDSB(t *testing.T, data []byte) (secretsType uint32, secretsData []byte, found bool) {
	t.Helper()
	off := 0
	for off+12 <= len(data) {
		blockType := binary.LittleEndian.Uint32(data[off : off+4])
		blockLen := binary.LittleEndian.Uint32(data[off+4 : off+8])
		if blockLen < 12 || off+int(blockLen) > len(data) {
			t.Fatalf("malformed block at offset %d: length %d", off, blockLen)
		}
		body := data[off+8 : off+int(blockLen)-4]
		if blockType == blockTypeDecryptionSecrets {
			if len(body) < 8 {
				t.Fatalf("DSB body too short: %d bytes", len(body))
			}
			st := binary.LittleEndian.Uint32(body[0:4])
			sl := binary.LittleEndian.Uint32(body[4:8])
			if int(sl) > len(body)-8 {
				t.Fatalf("DSB secrets_len %d exceeds body", sl)
			}
			return st, append([]byte(nil), body[8:8+sl]...), true
		}
		off += int(blockLen)
	}
	return 0, nil, false
}
