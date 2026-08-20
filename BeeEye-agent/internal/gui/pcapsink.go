package gui

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"BeeEye/internal/live"
)

// pcapSink persists every captured frame to a classic libpcap file on disk, so
// a packet's bytes survive being evicted from the in-memory ring. When the UI
// asks for the detail of an old packet, the Session reads the frame back from
// here and re-dissects it, instead of answering "no longer buffered".
//
// Why on disk at all: the ring is small (tens of thousands of packets) because
// dissected results are large and held in RAM; the raw frames are cheap to
// stream to a file and a laptop's /tmp holds far more of them. This is the same
// trade tcpdump -w makes.
//
// Two files are kept — the one being written and the one before it — so a
// rotation does not create a cliff where the packets just before it lose their
// detail. Anything older than the previous file is genuinely gone, bounded by
// maxBytes so /tmp cannot fill without limit.
type pcapSink struct {
	mu       sync.Mutex
	dir      string
	iface    string
	snaplen  uint32
	maxBytes int64

	cur      *os.File
	curW     *bufio.Writer
	curPath  string
	curIndex map[int64]int64 // packet No → byte offset of its record header
	curOff   int64

	prevPath  string
	prevIndex map[int64]int64

	closed bool
}

const pcapGlobalHeaderLen = 24
const pcapRecordHeaderLen = 16

// newPcapSink opens the first capture file under dir. A failure here is not
// fatal to capturing — the caller treats persistence as best-effort and falls
// back to the ring-only behaviour.
func newPcapSink(dir, iface string, snaplen uint32, maxBytes int64) (*pcapSink, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("pcapsink: mkdir %s: %w", dir, err)
	}
	s := &pcapSink{
		dir:       dir,
		iface:     iface,
		snaplen:   snaplen,
		maxBytes:  maxBytes,
		curIndex:  map[int64]int64{},
		prevIndex: map[int64]int64{},
	}
	if err := s.openNew(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *pcapSink) openNew() error {
	name := fmt.Sprintf("capture-%s.pcap", time.Now().Format("20060102-150405.000"))
	path := filepath.Join(s.dir, name)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("pcapsink: create %s: %w", path, err)
	}
	w := bufio.NewWriterSize(f, 1<<16)

	hdr := make([]byte, pcapGlobalHeaderLen)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // magic, µs resolution
	binary.LittleEndian.PutUint16(hdr[4:], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[16:], s.snaplen)
	binary.LittleEndian.PutUint32(hdr[20:], pcapLinkTypeEthernet)
	if _, err := w.Write(hdr); err != nil {
		f.Close()
		return err
	}
	s.cur = f
	s.curW = w
	s.curPath = path
	s.curIndex = map[int64]int64{}
	s.curOff = pcapGlobalHeaderLen
	return nil
}

// rotate closes the current file and starts a new one, keeping the file just
// closed as the readable "previous" and deleting anything older.
func (s *pcapSink) rotate() {
	s.curW.Flush()
	s.cur.Close()
	if s.prevPath != "" {
		os.Remove(s.prevPath) // the file older than "previous" is now unreachable
	}
	s.prevPath = s.curPath
	s.prevIndex = s.curIndex
	if err := s.openNew(); err != nil {
		// If a new file cannot be opened, keep serving reads from the two we
		// have but stop writing. Losing persistence is better than crashing
		// the capture.
		s.cur = nil
		s.curW = nil
	}
}

// Write appends one frame. Best-effort: a write error disables further writes
// but never propagates, because a full or unwritable /tmp must not stop the
// live capture the operator is watching.
func (s *pcapSink) Write(no int64, ts time.Time, origLen int, raw []byte) {
	if len(raw) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.curW == nil {
		return
	}
	if s.curOff+pcapRecordHeaderLen+int64(len(raw)) > s.maxBytes {
		s.rotate()
		if s.curW == nil {
			return
		}
	}

	rec := make([]byte, pcapRecordHeaderLen)
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(raw))) // captured length
	binary.LittleEndian.PutUint32(rec[12:], uint32(origLen)) // original length
	off := s.curOff
	if _, err := s.curW.Write(rec); err != nil {
		s.curW = nil
		return
	}
	if _, err := s.curW.Write(raw); err != nil {
		s.curW = nil
		return
	}
	s.curIndex[no] = off
	s.curOff += pcapRecordHeaderLen + int64(len(raw))
}

// Read recovers one frame by packet number as a live.Packet ready to be
// re-dissected. ok is false when the packet is in neither file.
func (s *pcapSink) Read(no int64) (live.Packet, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return live.Packet{}, false
	}
	if off, ok := s.curIndex[no]; ok {
		// The record may still be in the write buffer; flush so the read sees
		// it. Old packets are usually already flushed, but this is cheap.
		if s.curW != nil {
			s.curW.Flush()
		}
		return readRecord(s.curPath, off, no, s.iface)
	}
	if off, ok := s.prevIndex[no]; ok {
		return readRecord(s.prevPath, off, no, s.iface)
	}
	return live.Packet{}, false
}

func readRecord(path string, off, no int64, iface string) (live.Packet, bool) {
	f, err := os.Open(path)
	if err != nil {
		return live.Packet{}, false
	}
	defer f.Close()
	hdr := make([]byte, pcapRecordHeaderLen)
	if _, err := f.ReadAt(hdr, off); err != nil {
		return live.Packet{}, false
	}
	tsSec := binary.LittleEndian.Uint32(hdr[0:])
	tsUsec := binary.LittleEndian.Uint32(hdr[4:])
	capLen := binary.LittleEndian.Uint32(hdr[8:])
	origLen := binary.LittleEndian.Uint32(hdr[12:])
	if capLen == 0 || capLen > 1<<20 {
		return live.Packet{}, false
	}
	data := make([]byte, capLen)
	if _, err := f.ReadAt(data, off+pcapRecordHeaderLen); err != nil {
		return live.Packet{}, false
	}
	return live.Packet{
		Index:   no,
		TS:      time.Unix(int64(tsSec), int64(tsUsec)*1000),
		Iface:   iface,
		Data:    data,
		CapLen:  int(capLen),
		OrigLen: int(origLen),
	}, true
}

// Path reports the current capture file, for the status/UI to show where the
// traffic is being saved.
func (s *pcapSink) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.curPath
}

// Close flushes and closes the current file. The files are left on disk on
// purpose — they are the saved capture, and a fresh Start opens new ones.
func (s *pcapSink) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.curW != nil {
		s.curW.Flush()
	}
	if s.cur != nil {
		s.cur.Close()
	}
}
