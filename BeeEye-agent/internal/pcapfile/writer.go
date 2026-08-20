package pcapfile

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"
)

// Writer emits a classic libpcap file: the 24-byte little-endian,
// microsecond-resolution global header NewReader's first magic-number case
// decodes, followed by one 16-byte record header + raw bytes per packet. The
// natural write-side counterpart to Reader — used by F11's targeted,
// on-demand capture and by F44's PCAP export.
type Writer struct {
	w *bufio.Writer
}

// NewWriter writes the global header immediately and returns a Writer ready
// for WritePacket calls. linkType is one of the Link* constants.
func NewWriter(w io.Writer, linkType uint32, snapLen uint32) (*Writer, error) {
	bw := bufio.NewWriter(w)
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magic: little-endian, µs resolution
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // file format major version
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // file format minor version
	// hdr[8:12] thiszone and hdr[12:16] sigfigs are both left zero, as tcpdump writes them.
	binary.LittleEndian.PutUint32(hdr[16:20], snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkType)
	if _, err := bw.Write(hdr[:]); err != nil {
		return nil, err
	}
	return &Writer{w: bw}, nil
}

// WritePacket appends one record. ts is the capture time, data is the (possibly
// already snaplen-truncated) frame, and origLen is the length on the wire
// before any truncation — pass len(data) when the caller applied none.
func (w *Writer) WritePacket(ts time.Time, data []byte, origLen int) error {
	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(origLen))
	if _, err := w.w.Write(rec[:]); err != nil {
		return err
	}
	_, err := w.w.Write(data)
	return err
}

// Flush ensures every buffered byte reaches the underlying writer.
func (w *Writer) Flush() error { return w.w.Flush() }
