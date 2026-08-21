package pcapfile

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// writeNgBlock appends one length-framed pcapng block: type, total length,
// body, total length repeated — the shape every block in the format shares,
// which is what lets a reader skip a block type it does not understand.
func writeNgBlock(buf *bytes.Buffer, blockType uint32, body []byte) {
	total := uint32(12 + len(body))
	_ = binary.Write(buf, binary.LittleEndian, blockType)
	_ = binary.Write(buf, binary.LittleEndian, total)
	buf.Write(body)
	_ = binary.Write(buf, binary.LittleEndian, total)
}

func ngOption(code, value uint16, data []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, code)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(data)))
	buf.Write(data)
	if pad := (4 - len(data)%4) % 4; pad > 0 {
		buf.Write(make([]byte, pad))
	}
	return buf.Bytes()
}

// buildTestPcapng assembles a minimal-but-real file by hand — independent of
// the reader it tests: Section Header Block, one Interface Description
// Block (tsResolOpt lets a test ask for a non-default resolution, e.g. 0x09
// for nanoseconds; nil means "don't send if_tsresol, use the format
// default"), an unrecognised block type a real reader must skip over
// without losing its place, and two Enhanced Packet Blocks.
func buildTestPcapng(t *testing.T, tsResolOpt []byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	shb := make([]byte, 0, 16)
	shb = binary.LittleEndian.AppendUint32(shb, sectionHeaderMagicLE)
	shb = binary.LittleEndian.AppendUint16(shb, 1) // major
	shb = binary.LittleEndian.AppendUint16(shb, 0) // minor
	shb = binary.LittleEndian.AppendUint64(shb, 0xFFFFFFFFFFFFFFFF)
	writeNgBlock(&buf, blockTypeSectionHeader, shb)

	idb := make([]byte, 0, 16)
	idb = binary.LittleEndian.AppendUint16(idb, 1) // LinkType = Ethernet
	idb = binary.LittleEndian.AppendUint16(idb, 0) // reserved
	idb = binary.LittleEndian.AppendUint32(idb, 65535)
	if tsResolOpt != nil {
		idb = append(idb, ngOption(optIfTsresol, 0, tsResolOpt)...)
	}
	writeNgBlock(&buf, blockTypeInterfaceDesc, idb)

	// A block type this reader has no use for (Name Resolution Block, 0x04)
	// — Next() must skip exactly its declared length and pick right back up
	// with the packet that follows, not get lost.
	writeNgBlock(&buf, 0x00000004, []byte{0xAA, 0xBB, 0xCC, 0xDD})

	pkt1 := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	epb1 := make([]byte, 0, 20+8)
	epb1 = binary.LittleEndian.AppendUint32(epb1, 0)       // interface id
	epb1 = binary.LittleEndian.AppendUint32(epb1, 0)       // ts high
	epb1 = binary.LittleEndian.AppendUint32(epb1, 1000000) // ts low
	epb1 = binary.LittleEndian.AppendUint32(epb1, uint32(len(pkt1)))
	epb1 = binary.LittleEndian.AppendUint32(epb1, uint32(len(pkt1)))
	epb1 = append(epb1, pkt1...)
	if pad := (4 - len(pkt1)%4) % 4; pad > 0 {
		epb1 = append(epb1, make([]byte, pad)...)
	}
	writeNgBlock(&buf, blockTypeEnhancedPacket, epb1)

	pkt2 := []byte{0x01, 0x02, 0x03}
	epb2 := make([]byte, 0, 20+4)
	epb2 = binary.LittleEndian.AppendUint32(epb2, 0)
	epb2 = binary.LittleEndian.AppendUint32(epb2, 0)
	epb2 = binary.LittleEndian.AppendUint32(epb2, 2000000)
	epb2 = binary.LittleEndian.AppendUint32(epb2, uint32(len(pkt2)))
	epb2 = binary.LittleEndian.AppendUint32(epb2, uint32(len(pkt2))+10) // OrigLen > CapLen: truncated capture
	epb2 = append(epb2, pkt2...)
	if pad := (4 - len(pkt2)%4) % 4; pad > 0 {
		epb2 = append(epb2, make([]byte, pad)...)
	}
	writeNgBlock(&buf, blockTypeEnhancedPacket, epb2)

	return buf.Bytes()
}

func TestNgReaderDefaultResolution(t *testing.T) {
	data := buildTestPcapng(t, nil) // no if_tsresol → microsecond default
	pr, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	p1, err := pr.Next()
	if err != nil {
		t.Fatalf("Next (packet 1): %v", err)
	}
	if !bytes.Equal(p1.Data, []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}) {
		t.Errorf("packet 1 data = %x, want deadbeef0102", p1.Data)
	}
	if p1.CapLen != 6 || p1.OrigLen != 6 {
		t.Errorf("packet 1 CapLen=%d OrigLen=%d, want 6,6", p1.CapLen, p1.OrigLen)
	}
	wantTS := time.Unix(0, 1_000_000*1000) // 1,000,000 µs = 1s
	if !p1.TS.Equal(wantTS) {
		t.Errorf("packet 1 ts = %v, want %v (1e6 ticks at microsecond resolution)", p1.TS, wantTS)
	}

	p2, err := pr.Next()
	if err != nil {
		t.Fatalf("Next (packet 2): %v", err)
	}
	if p2.CapLen != 3 || p2.OrigLen != 13 {
		t.Errorf("packet 2 CapLen=%d OrigLen=%d, want 3,13 (a truncated capture)", p2.CapLen, p2.OrigLen)
	}

	if _, err := pr.Next(); err != io.EOF {
		t.Errorf("Next after the last packet = %v, want io.EOF", err)
	}
}

func TestNgReaderNanosecondResolution(t *testing.T) {
	// if_tsresol = 9 → 10^-9 seconds per tick (top bit clear = power of ten).
	data := buildTestPcapng(t, []byte{9})
	pr, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p1, err := pr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	// 1,000,000 ticks at 1ns each = 1ms, not the 1s the default-resolution
	// test above expects from the identical raw tick value — this is
	// exactly the bug a reader that ignores if_tsresol would have.
	wantTS := time.Unix(0, 1_000_000)
	if !p1.TS.Equal(wantTS) {
		t.Errorf("packet 1 ts = %v, want %v (1e6 ticks at nanosecond resolution)", p1.TS, wantTS)
	}
}

// TestNgReaderPropagatesLinkType guards the bug this was written for: a
// capture from a tunnel/VPN interface (vtiN, tun, …) commonly declares
// LINKTYPE_RAW rather than Ethernet, and a reader that silently assumed
// Ethernet for every interface handed the dissector an IP header it then
// misread as a bogus Ethernet header — real src/dst addresses replaced by
// garbage MACs, everything past that undissected. The per-interface
// LinkType has to reach each Packet the IDB's interface produces.
func TestNgReaderPropagatesLinkType(t *testing.T) {
	var buf bytes.Buffer

	shb := make([]byte, 0, 16)
	shb = binary.LittleEndian.AppendUint32(shb, sectionHeaderMagicLE)
	shb = binary.LittleEndian.AppendUint16(shb, 1)
	shb = binary.LittleEndian.AppendUint16(shb, 0)
	shb = binary.LittleEndian.AppendUint64(shb, 0xFFFFFFFFFFFFFFFF)
	writeNgBlock(&buf, blockTypeSectionHeader, shb)

	idb := make([]byte, 0, 8)
	idb = binary.LittleEndian.AppendUint16(idb, LinkRaw) // 101, not Ethernet
	idb = binary.LittleEndian.AppendUint16(idb, 0)
	idb = binary.LittleEndian.AppendUint32(idb, 65535)
	writeNgBlock(&buf, blockTypeInterfaceDesc, idb)

	pkt := []byte{0x45, 0x00, 0x00, 0x14} // start of a bare IPv4 header, no Ethernet
	epb := make([]byte, 0, 20+4)
	epb = binary.LittleEndian.AppendUint32(epb, 0) // interface id
	epb = binary.LittleEndian.AppendUint32(epb, 0)
	epb = binary.LittleEndian.AppendUint32(epb, 0)
	epb = binary.LittleEndian.AppendUint32(epb, uint32(len(pkt)))
	epb = binary.LittleEndian.AppendUint32(epb, uint32(len(pkt)))
	epb = append(epb, pkt...)
	writeNgBlock(&buf, blockTypeEnhancedPacket, epb)

	pr, err := Open(&buf)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p, err := pr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if p.LinkType != LinkRaw {
		t.Errorf("packet LinkType = %d, want %d (LinkRaw) — the IDB's own LinkType was not propagated", p.LinkType, LinkRaw)
	}
}

func TestOpenDetectsClassicPcapStillWorks(t *testing.T) {
	// A minimal classic pcap header (microsecond, little-endian) with no
	// packets — Open must still hand back a *Reader, not try to parse it as
	// pcapng just because a new code path now exists.
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2)) // major
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4)) // minor
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // thiszone
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // sigfigs
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(LinkEthernet))

	pr, err := Open(&buf)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := pr.(*Reader); !ok {
		t.Errorf("Open on a classic pcap header returned %T, want *Reader", pr)
	}
	if _, err := pr.Next(); err != io.EOF {
		t.Errorf("Next on an empty capture = %v, want io.EOF", err)
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	if _, err := Open(bytes.NewReader([]byte("not a capture file"))); err != ErrNotPcap {
		t.Errorf("Open on garbage = %v, want ErrNotPcap", err)
	}
}
