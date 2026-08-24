// ngwriter.go writes pcapng files — the write-side counterpart to
// NgReader in pcapng.go, added for F14 phase two: a Decryption Secrets
// Block (DSB) lets a capture and the TLS key-log lines that decrypt it
// travel in one Wireshark-openable file, instead of the two separate files
// (.pcap + keys-*.log) scripts/tls-decrypt.sh has always produced. Classic
// pcap has no block type that can carry this, which is why the merge output
// is pcapng rather than another classic pcap file.
//
// Only a Section Header Block, one Interface Description Block, Enhanced
// Packet Blocks and (optionally) one Decryption Secrets Block are written —
// exactly the block types NgReader understands plus the DSB, which any
// pcapng reader (including this package's own) safely skips if it does not
// care about secrets. Multiple interfaces, comments and other options are
// out of scope: this writer exists to produce the one file BeeEye's own
// tools need, not to be a general pcapng encoder.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"
)

// SecretsTypeTLS is the pcapng Decryption Secrets Block "Secrets Type" value
// Wireshark uses for TLS key-log-format secrets (the same lines
// SSLKEYLOGFILE produces) — 0x544c534b, ASCII "TLSK". Defined by Wireshark's
// wiretap/secrets-types.h (SECRETS_TYPE_TLS); there is no separate IETF
// pcapng RFC value for this, secrets types are a Wireshark-maintained
// registry the format's own spec defers to.
const SecretsTypeTLS = 0x544c534b

// NgWriter emits a pcapng file with a single interface. NewNgWriter writes
// the Section Header Block and Interface Description Block immediately, so
// timestamps that follow always have exactly one interface (ID 0) to
// resolve against.
type NgWriter struct {
	w   *bufio.Writer
	err error // sticky: once a Write fails, every later call is a no-op
}

// NewNgWriter writes the Section Header and Interface Description Blocks and
// returns a Writer ready for WritePacket / WriteSecrets calls. linkType is
// one of the Link* constants; snapLen is the per-packet capture limit (0
// means "unlimited" per the pcapng spec). No if_tsresol option is written,
// so the file uses the format default resolution (microseconds) — the same
// resolution WritePacket's time.Time is truncated to, and the same default
// NgReader assumes for an interface that declares none.
func NewNgWriter(w io.Writer, linkType uint32, snapLen uint32) (*NgWriter, error) {
	bw := bufio.NewWriterSize(w, 64<<10)
	nw := &NgWriter{w: bw}

	shb := make([]byte, 0, 16)
	shb = binary.LittleEndian.AppendUint32(shb, sectionHeaderMagicLE)
	shb = binary.LittleEndian.AppendUint16(shb, 1)                  // major
	shb = binary.LittleEndian.AppendUint16(shb, 0)                  // minor
	shb = binary.LittleEndian.AppendUint64(shb, 0xFFFFFFFFFFFFFFFF) // section length: unknown
	nw.writeBlock(blockTypeSectionHeader, shb)

	idb := make([]byte, 0, 8)
	idb = binary.LittleEndian.AppendUint16(idb, uint16(linkType))
	idb = binary.LittleEndian.AppendUint16(idb, 0) // reserved
	idb = binary.LittleEndian.AppendUint32(idb, snapLen)
	nw.writeBlock(blockTypeInterfaceDesc, idb)

	if nw.err != nil {
		return nil, nw.err
	}
	return nw, nil
}

// WritePacket appends one Enhanced Packet Block on interface 0. ts is the
// capture time (truncated to microsecond resolution — see NewNgWriter);
// data is the (possibly already snaplen-truncated) frame; origLen is the
// length on the wire before any truncation.
func (nw *NgWriter) WritePacket(ts time.Time, data []byte, origLen int) error {
	if nw.err != nil {
		return nw.err
	}
	ticks := uint64(ts.UnixMicro())
	body := make([]byte, 0, 20+len(data)+3)
	body = binary.LittleEndian.AppendUint32(body, 0) // interface id
	body = binary.LittleEndian.AppendUint32(body, uint32(ticks>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(ticks))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)))
	body = binary.LittleEndian.AppendUint32(body, uint32(origLen))
	body = append(body, data...)
	body = appendPad4(body)
	nw.writeBlock(blockTypeEnhancedPacket, body)
	return nw.err
}

// WriteSecrets appends one Decryption Secrets Block carrying data verbatim
// (e.g. the raw bytes of a keys-*.log SSLKEYLOGFILE, for secretsType
// SecretsTypeTLS). Per the pcapng spec, DSBs SHOULD precede the packet
// blocks whose decryption they enable; call this before any WritePacket
// calls if the caller can arrange that, though nothing here enforces it —
// Wireshark tolerates a DSB anywhere in the file in practice.
func (nw *NgWriter) WriteSecrets(secretsType uint32, data []byte) error {
	if nw.err != nil {
		return nw.err
	}
	body := make([]byte, 0, 8+len(data)+3)
	body = binary.LittleEndian.AppendUint32(body, secretsType)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	body = appendPad4(body)
	nw.writeBlock(blockTypeDecryptionSecrets, body)
	return nw.err
}

// Flush ensures every buffered byte reaches the underlying writer.
func (nw *NgWriter) Flush() error {
	if nw.err != nil {
		return nw.err
	}
	if err := nw.w.Flush(); err != nil {
		nw.err = err
	}
	return nw.err
}

// writeBlock frames body as one length-prefixed-and-suffixed pcapng block —
// the shape every block type shares (Block Type, Block Total Length, Body,
// Block Total Length again) — and records the first write error, if any, so
// callers don't need to check every intermediate binary.Write themselves.
func (nw *NgWriter) writeBlock(blockType uint32, body []byte) {
	if nw.err != nil {
		return
	}
	total := uint32(12 + len(body))
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], blockType)
	binary.LittleEndian.PutUint32(hdr[4:8], total)
	if _, err := nw.w.Write(hdr[:]); err != nil {
		nw.err = err
		return
	}
	if _, err := nw.w.Write(body); err != nil {
		nw.err = err
		return
	}
	if err := binary.Write(nw.w, binary.LittleEndian, total); err != nil {
		nw.err = err
	}
}

// appendPad4 pads b to a 4-byte boundary with zero bytes, as every pcapng
// block body must be before its trailing Block Total Length.
func appendPad4(b []byte) []byte {
	if pad := (4 - len(b)%4) % 4; pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}
