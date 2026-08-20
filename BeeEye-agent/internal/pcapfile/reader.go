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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link-layer types this reader understands.
const (
	LinkEthernet = 1
	LinkRaw      = 101 // raw IP, no link header
	LinkLinuxSLL = 113 // "any" pseudo-device
)

var (
	// ErrNotPcap means the magic number did not match any known variant —
	// most often a pcapng file, which is a different format entirely.
	ErrNotPcap = errors.New("pcapfile: not a classic libpcap file (a pcapng file needs conversion: editcap -F pcap in.pcapng out.pcap)")
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
	Index   int64
	TS      time.Time
	Data    []byte
	CapLen  int
	OrigLen int
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
		Index:   r.index,
		TS:      time.Unix(int64(sec), nsec),
		Data:    data,
		CapLen:  int(capLen),
		OrigLen: int(origLen),
	}, nil
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
