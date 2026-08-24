// pcapng.go reads pcapng capture files — the block-based format modern
// Wireshark and dumpcap write by default, distinct from (and not a simple
// variant of) the classic libpcap format reader.go handles.
//
// Only what BeeEye needs is implemented: the Section Header Block (just
// enough to establish byte order), Interface Description Blocks (just
// enough to know each interface's timestamp resolution, since Enhanced
// Packet Blocks reference it by ID rather than repeating it), and
// Enhanced/Simple Packet Blocks. Every other block type a real capture can
// carry — name resolution, interface statistics, decryption secrets,
// custom blocks — is skipped by its declared length rather than parsed:
// none of them are a packet to dissect, and pcapng's block-length framing
// is deliberately designed to make "skip what you don't understand" cheap
// and safe.

package pcapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

const (
	blockTypeSectionHeader     = 0x0A0D0D0A
	blockTypeInterfaceDesc     = 0x00000001
	blockTypeSimplePacket      = 0x00000003
	blockTypeEnhancedPacket    = 0x00000006
	blockTypeDecryptionSecrets = 0x0000000A

	sectionHeaderMagicLE = 0x1A2B3C4D
	sectionHeaderMagicBE = 0x4D3C2B1A // the same 4 bytes read the other way round

	// optIfTsresol is the Interface Description Block option carrying the
	// timestamp resolution for that interface. Absent means the format's own
	// default: microseconds.
	optIfTsresol      = 9
	defaultTsResolSec = 1e-6
)

// ngInterface is what a packet block needs from the Interface Description
// Block that declared it: the timestamp resolution (how a packet's own
// timestamp bytes are interpreted) and the link type (how Data's own bytes
// are framed — Ethernet, raw IP, Linux "cooked capture", etc.; see
// dissect.Packet, which is what actually branches on it).
type ngInterface struct {
	tsResolSec float64
	linkType   uint32
}

// NgReader streams packets out of a pcapng file.
type NgReader struct {
	r      *bufio.Reader
	order  binary.ByteOrder
	index  int64
	ifaces []ngInterface
	maxLen uint32
}

// NewNgReader reads and validates the file's Section Header Block. r may
// already be a *bufio.Reader (Open passes its own along); anything else is
// wrapped once here.
func NewNgReader(r io.Reader) (*NgReader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64<<10)
	}

	// The Section Header Block's own Block Total Length is meaningless until
	// byte order is known, and byte order isn't known until the magic 4
	// bytes inside the body are read — so peek far enough to read the magic
	// before committing to an interpretation of the length field next to it.
	head, err := br.Peek(12)
	if err != nil {
		return nil, ErrNotPcap
	}
	if binary.LittleEndian.Uint32(head[0:4]) != blockTypeSectionHeader {
		return nil, ErrNotPcap
	}
	order, err := byteOrderFromMagic(binary.LittleEndian.Uint32(head[8:12]))
	if err != nil {
		return nil, err
	}
	blockLen := order.Uint32(head[4:8])
	if blockLen < 12 || blockLen > MaxPacketBytes {
		return nil, ErrTruncated
	}
	// The whole Section Header Block is skippable now that its one useful
	// fact (byte order) has been read — nothing else in it changes how a
	// packet block is parsed.
	if _, err := br.Discard(int(blockLen)); err != nil {
		return nil, ErrTruncated
	}
	return &NgReader{r: br, order: order, maxLen: MaxPacketBytes}, nil
}

func byteOrderFromMagic(magicReadLE uint32) (binary.ByteOrder, error) {
	switch magicReadLE {
	case sectionHeaderMagicLE:
		return binary.LittleEndian, nil
	case sectionHeaderMagicBE:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("pcapfile: pcapng section header has an unrecognised byte-order magic")
	}
}

// Next returns the next packet, or io.EOF at the end of the file.
func (nr *NgReader) Next() (*Packet, error) {
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(nr.r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, ErrTruncated
			}
			return nil, err
		}
		blockType := nr.order.Uint32(hdr[0:4])
		blockLen := nr.order.Uint32(hdr[4:8])
		if blockLen < 12 || blockLen > nr.maxLen {
			return nil, fmt.Errorf("pcapfile: pcapng block claims %d bytes, exceeding the %d byte limit — the file is corrupt", blockLen, nr.maxLen)
		}
		// Block Total Length counts the type field, itself, the body, and
		// its own trailing repeat (8 + body + 4) — the header above already
		// consumed the first 8, so what remains to account for is bodyLen+4.
		bodyLen := int(blockLen) - 12

		switch blockType {
		case blockTypeSectionHeader:
			// A second section starting mid-file (multiple captures
			// concatenated, which pcapng explicitly allows) — re-establish
			// byte order exactly as NewNgReader did, and forget interface
			// IDs from the previous section, since they are section-scoped.
			if bodyLen < 4 {
				return nil, ErrTruncated
			}
			var magic [4]byte
			if _, err := io.ReadFull(nr.r, magic[:]); err != nil {
				return nil, ErrTruncated
			}
			order, err := byteOrderFromMagic(binary.LittleEndian.Uint32(magic[:]))
			if err != nil {
				return nil, err
			}
			nr.order = order
			if err := nr.discard(bodyLen - 4 + 4); err != nil { // rest of body + trailing length
				return nil, err
			}
			nr.ifaces = nil
			continue

		case blockTypeInterfaceDesc:
			body := make([]byte, bodyLen)
			if _, err := io.ReadFull(nr.r, body); err != nil {
				return nil, ErrTruncated
			}
			if err := nr.discard(4); err != nil { // trailing length
				return nil, err
			}
			nr.ifaces = append(nr.ifaces, ngInterface{
				tsResolSec: parseTsResol(nr.order, body),
				linkType:   ngLinkType(nr.order, body),
			})
			continue

		case blockTypeEnhancedPacket:
			if bodyLen < 20 {
				return nil, ErrTruncated
			}
			body := make([]byte, bodyLen)
			if _, err := io.ReadFull(nr.r, body); err != nil {
				return nil, ErrTruncated
			}
			if err := nr.discard(4); err != nil {
				return nil, err
			}
			ifaceID := nr.order.Uint32(body[0:4])
			tsHigh := nr.order.Uint32(body[4:8])
			tsLow := nr.order.Uint32(body[8:12])
			capLen := nr.order.Uint32(body[12:16])
			origLen := nr.order.Uint32(body[16:20])
			if 20+int(capLen) > len(body) {
				return nil, ErrTruncated
			}
			resol := defaultTsResolSec
			linkType := uint32(LinkEthernet)
			if int(ifaceID) < len(nr.ifaces) {
				resol = nr.ifaces[ifaceID].tsResolSec
				linkType = nr.ifaces[ifaceID].linkType
			}
			nr.index++
			return &Packet{
				Index:    nr.index,
				TS:       ngTimestamp(tsHigh, tsLow, resol),
				Data:     body[20 : 20+capLen],
				LinkType: linkType,
				CapLen:   int(capLen),
				OrigLen:  int(origLen),
			}, nil

		case blockTypeSimplePacket:
			// Simple Packet Blocks carry no interface ID or timestamp — the
			// format's own trade for a smaller per-packet header — so there
			// is nothing to look up and no time to report; a zero Time
			// says "unknown" honestly rather than inventing one.
			if bodyLen < 4 {
				return nil, ErrTruncated
			}
			body := make([]byte, bodyLen)
			if _, err := io.ReadFull(nr.r, body); err != nil {
				return nil, ErrTruncated
			}
			if err := nr.discard(4); err != nil {
				return nil, err
			}
			origLen := nr.order.Uint32(body[0:4])
			capLen := uint32(len(body) - 4)
			if capLen > origLen {
				capLen = origLen
			}
			// Simple Packet Blocks implicitly belong to interface 0 — the
			// format allows them only when the section has exactly one
			// interface, precisely so there is nothing to look up.
			linkType := uint32(LinkEthernet)
			if len(nr.ifaces) > 0 {
				linkType = nr.ifaces[0].linkType
			}
			nr.index++
			return &Packet{
				Index:    nr.index,
				TS:       time.Time{},
				Data:     body[4 : 4+capLen],
				LinkType: linkType,
				CapLen:   int(capLen),
				OrigLen:  int(origLen),
			}, nil

		default:
			// Name resolution, interface statistics, decryption secrets,
			// custom blocks, anything else this reader has no use for.
			if err := nr.discard(bodyLen + 4); err != nil {
				return nil, err
			}
			continue
		}
	}
}

func (nr *NgReader) discard(n int) error {
	if n < 0 {
		return ErrTruncated
	}
	if _, err := nr.r.Discard(n); err != nil {
		if errors.Is(err, io.EOF) {
			return ErrTruncated
		}
		return err
	}
	return nil
}

// ngTimestamp combines an Enhanced Packet Block's split 64-bit tick count
// with the resolution its interface declared (or the format default).
func ngTimestamp(high, low uint32, resolSec float64) time.Time {
	ticks := uint64(high)<<32 | uint64(low)
	total := float64(ticks) * resolSec
	sec := int64(total)
	nsec := int64((total - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}

// ngLinkType reads an Interface Description Block's fixed LinkType field —
// the first 2 bytes of the body, unlike if_tsresol below which is an
// optional trailing TLV. Too-short bodies (shouldn't happen; IDB is defined
// to always have at least LinkType+Reserved+SnapLen) fall back to Ethernet,
// matching every other soft-fallback in this reader.
func ngLinkType(order binary.ByteOrder, idbBody []byte) uint32 {
	if len(idbBody) < 2 {
		return LinkEthernet
	}
	return uint32(order.Uint16(idbBody[0:2]))
}

// parseTsResol scans an Interface Description Block's options for
// if_tsresol (option code 9): one byte, a power of ten with the top bit
// clear or a power of two with it set (RFC-draft pcapng §4.2). Absent means
// the format's own default, microseconds.
func parseTsResol(order binary.ByteOrder, idbBody []byte) float64 {
	// LinkType(2) + Reserved(2) + SnapLen(4) precede the options.
	if len(idbBody) < 8 {
		return defaultTsResolSec
	}
	opts := idbBody[8:]
	for len(opts) >= 4 {
		code := order.Uint16(opts[0:2])
		length := int(order.Uint16(opts[2:4]))
		opts = opts[4:]
		if code == 0 { // opt_endofopt
			break
		}
		if length > len(opts) {
			break
		}
		if code == optIfTsresol && length >= 1 {
			v := opts[0]
			if v&0x80 != 0 {
				return math.Pow(2, -float64(v&0x7f))
			}
			return math.Pow(10, -float64(v))
		}
		// Options are padded to a 4-byte boundary.
		opts = opts[(length+3)&^3:]
	}
	return defaultTsResolSec
}
