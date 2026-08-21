// Package pcapfile reads classic libpcap capture files.
//
// It is deliberately small and dependency-free: BeeEye already writes this
// format (internal/gui exports it), so reading it back is symmetric, and
// pulling in a capture library to parse a 24-byte header would be a poor trade.
//
// Both byte orders and both timestamp resolutions are handled, because files
// arrive from other people's tools, not just from BeeEye.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link-layer types this reader understands.
const (
	LinkEthernet = 1
	// LinkRawBSD is DLT_RAW as historically used by libpcap/tcpdump on Linux
	// and various BSDs — raw IP, no link header — before LINKTYPE_RAW (101)
	// was standardized as a distinct, platform-independent value. Files from
	// dumpcap on a tunnel/VPN-type interface (vtiN and similar) commonly
	// carry this value rather than 101; both mean exactly the same thing and
	// must be treated identically (see dissect.Packet).
	LinkRawBSD   = 12
	LinkRaw      = 101 // raw IP, no link header (the standardized LINKTYPE_RAW)
	LinkLinuxSLL = 113 // "any" pseudo-device
)

var (
	// ErrNotPcap means the magic number did not match classic pcap or
	// pcapng (see Open, which recognises both) — the file is neither, or is
	// truncated before its first 4 bytes.
	ErrNotPcap = errors.New("pcapfile: not a recognised capture file (neither classic pcap nor pcapng)")
	// ErrTruncated means the file ended mid-record.
	ErrTruncated = errors.New("pcapfile: file ends mid-packet")
)

// Header describes the capture as a whole.
type Header struct {
	MajorVersion uint16
	MinorVersion uint16
	SnapLen      uint32
	LinkType     uint32
	Nanosecond   bool // timestamps are ns rather than µs
	BigEndian    bool
}

// Packet is one record.
type Packet struct {
	Index int64
	TS    time.Time
	Data  []byte
	// LinkType is the LINKTYPE_* of Data's own framing (see the Link-layer
	// types const block above) — a classic pcap file carries one for the
	// whole file, pcapng one per interface, so this is set per packet even
	// though in practice it is almost always constant across an entire
	// replay. dissect.Packet treats live.Packet's zero value (never
	// explicitly set on the live AF_PACKET/eBPF capture path, which is
	// always genuine Ethernet) the same as LinkEthernet, so this is not a
	// special "unset" sentinel here — a classic pcap file whose header
	// genuinely says LINKTYPE_NULL (0, BSD loopback) is not something either
	// reader distinguishes from "unset"; that encapsulation is not one this
	// analyzer targets.
	LinkType uint32
	CapLen   int
	OrigLen  int
}

// Reader streams packets out of a libpcap file.
type Reader struct {
	r      io.Reader
	hdr    Header
	order  binary.ByteOrder
	index  int64
	maxLen uint32
}

// MaxPacketBytes caps a single record. A corrupt or hostile length field would
// otherwise ask us to allocate whatever 32-bit number it contains.
const MaxPacketBytes = 16 << 20

// NewReader reads and validates the file header.
func NewReader(r io.Reader) (*Reader, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, ErrNotPcap
	}

	var order binary.ByteOrder
	var nano bool
	switch binary.LittleEndian.Uint32(magic[:]) {
	case 0xa1b2c3d4:
		order, nano = binary.LittleEndian, false
	case 0xa1b23c4d:
		order, nano = binary.LittleEndian, true
	case 0xd4c3b2a1:
		order, nano = binary.BigEndian, false
	case 0x4d3cb2a1:
		order, nano = binary.BigEndian, true
	default:
		return nil, ErrNotPcap
	}

	rest := make([]byte, 20)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, ErrTruncated
	}

	hdr := Header{
		MajorVersion: order.Uint16(rest[0:2]),
		MinorVersion: order.Uint16(rest[2:4]),
		SnapLen:      order.Uint32(rest[12:16]),
		LinkType:     order.Uint32(rest[16:20]),
		Nanosecond:   nano,
		BigEndian:    order == binary.BigEndian,
	}
	return &Reader{r: r, hdr: hdr, order: order, maxLen: MaxPacketBytes}, nil
}

// Header returns the file header.
func (r *Reader) Header() Header { return r.hdr }

// Next returns the next packet, or io.EOF at the end of the file.
func (r *Reader) Next() (*Packet, error) {
	var rec [16]byte
	if _, err := io.ReadFull(r.r, rec[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrTruncated
		}
		return nil, err
	}

	sec := r.order.Uint32(rec[0:4])
	frac := r.order.Uint32(rec[4:8])
	capLen := r.order.Uint32(rec[8:12])
	origLen := r.order.Uint32(rec[12:16])

	if capLen > r.maxLen {
		return nil, fmt.Errorf("pcapfile: record %d claims %d bytes, which exceeds the %d byte limit — the file is corrupt",
			r.index+1, capLen, r.maxLen)
	}

	data := make([]byte, capLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return nil, ErrTruncated
	}

	nsec := int64(frac) * 1000
	if r.hdr.Nanosecond {
		nsec = int64(frac)
	}

	r.index++
	return &Packet{
		Index:    r.index,
		TS:       time.Unix(int64(sec), nsec),
		Data:     data,
		LinkType: r.hdr.LinkType,
		CapLen:   int(capLen),
		OrigLen:  int(origLen),
	}, nil
}

// PacketReader is what both Reader (classic pcap) and NgReader (pcapng)
// implement — the only thing a caller that just wants packets out of a
// capture file needs, regardless of which of the two formats it turns out
// to be.
type PacketReader interface {
	Next() (*Packet, error)
}

// Open auto-detects the capture format — classic pcap or pcapng, the two
// formats Wireshark, tcpdump and dumpcap actually write — from the first
// bytes, and returns the matching reader. Prefer this over calling
// NewReader/NewNgReader directly unless the format is already known; a file
// someone hands you could be either; a person opening one to look at it
// should not need to know the difference or run a converter first.
func Open(r io.Reader) (PacketReader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(4)
	if err != nil {
		return nil, ErrNotPcap
	}
	if binary.LittleEndian.Uint32(head) == blockTypeSectionHeader {
		return NewNgReader(br)
	}
	return NewReader(br)
}

// LinkTypeName renders the link type for display.
func LinkTypeName(t uint32) string {
	switch t {
	case LinkEthernet:
		return "Ethernet"
	case LinkRaw:
		return "Raw IP"
	case LinkLinuxSLL:
		return "Linux cooked capture"
	}
	return fmt.Sprintf("LINKTYPE_%d", t)
}
