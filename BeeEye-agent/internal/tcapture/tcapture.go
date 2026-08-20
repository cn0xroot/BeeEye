// Package tcapture implements F11: a bounded, on-demand capture of one
// device's traffic. This is distinct from F44 (PCAP export), which exports
// whatever the rolling ring buffer already happens to hold — a targeted
// capture starts a fresh, MAC-filtered pcap file the moment it's requested
// and writes to it live, for a caller-chosen duration or byte budget.
// Nothing beyond small counters is held in memory; everything else streams
// straight to disk.
package tcapture

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"BeeEye/internal/live"
	"BeeEye/internal/pcapfile"
)

const (
	// MaxDuration bounds a single session so a forgotten request cannot
	// capture indefinitely and fill the disk.
	MaxDuration = 30 * time.Minute
	// MaxBytesCap is the hard ceiling on max_bytes regardless of what the
	// caller asks for, for the same reason.
	MaxBytesCap = 512 << 20 // 512MiB
)

// Session is one running or finished targeted capture.
type Session struct {
	ID       string
	MAC      string
	Started  time.Time
	Deadline time.Time
	MaxBytes int64

	mu      sync.Mutex
	f       *os.File
	w       *pcapfile.Writer
	path    string
	packets int64
	bytes   int64
	done    bool
	err     string
	timer   *time.Timer
}

// Status is the JSON-safe snapshot a status/list endpoint returns.
type Status struct {
	ID       string    `json:"id"`
	MAC      string    `json:"mac"`
	Started  time.Time `json:"started"`
	Deadline time.Time `json:"deadline"`
	Packets  int64     `json:"packets"`
	Bytes    int64     `json:"bytes"`
	Done     bool      `json:"done"`
	Error    string    `json:"error,omitempty"`
}

func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{ID: s.ID, MAC: s.MAC, Started: s.Started, Deadline: s.Deadline,
		Packets: s.packets, Bytes: s.bytes, Done: s.done, Error: s.err}
}

// Path returns the on-disk pcap file. Readable once Status().Done is true;
// reading it mid-capture is also fine (WritePacket appends whole records),
// just may miss the final partially-buffered one until the next flush.
func (s *Session) Path() string { return s.path }

// closeLocked finalizes the file. Must be called with s.mu held. Safe to
// call more than once — the deadline timer and a byte-cap trip in feed can
// both race to close the same session.
func (s *Session) closeLocked(reason string) {
	if s.done {
		return
	}
	s.done = true
	if s.timer != nil {
		s.timer.Stop()
	}
	_ = s.w.Flush()
	_ = s.f.Close()
	if reason != "" {
		s.err = reason
	}
}

// feed writes pkt into the session if it is still open.
func (s *Session) feed(pkt live.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	if err := s.w.WritePacket(pkt.TS, pkt.Data, pkt.OrigLen); err != nil {
		s.closeLocked(err.Error())
		return
	}
	s.packets++
	s.bytes += int64(len(pkt.Data))
	if s.bytes >= s.MaxBytes {
		s.closeLocked("")
	}
}

// Manager tracks the set of active/recent targeted-capture sessions.
type Manager struct {
	dir      string
	snaplen  uint32
	linkType uint32

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager creates a manager that writes session files under dir.
func NewManager(dir string, linkType uint32, snaplen uint32) *Manager {
	return &Manager{dir: dir, linkType: linkType, snaplen: snaplen, sessions: map[string]*Session{}}
}

func randID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Start begins a new session capturing every frame whose source or
// destination MAC equals mac, for at most duration or maxBytes, whichever
// comes first. Both bounds are clamped to sane ceilings (MaxDuration,
// MaxBytesCap) so a UI bug or a stale form value cannot fill the disk or
// capture forever.
func (m *Manager) Start(mac string, duration time.Duration, maxBytes int64) (*Session, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	if duration <= 0 || duration > MaxDuration {
		duration = MaxDuration
	}
	if maxBytes <= 0 || maxBytes > MaxBytesCap {
		maxBytes = MaxBytesCap
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return nil, fmt.Errorf("tcapture: mkdir %s: %w", m.dir, err)
	}

	id := randID()
	path := filepath.Join(m.dir, fmt.Sprintf("targeted-%s-%s.pcap", hw.String(), id))
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("tcapture: create %s: %w", path, err)
	}
	w, err := pcapfile.NewWriter(f, m.linkType, m.snaplen)
	if err != nil {
		f.Close()
		return nil, err
	}

	now := time.Now()
	s := &Session{
		ID: id, MAC: hw.String(), Started: now, Deadline: now.Add(duration),
		MaxBytes: maxBytes, f: f, w: w, path: path,
	}
	// AfterFunc's callback can in principle fire before AfterFunc itself
	// returns (a duration of ~0), which would race a plain "s.timer = ..."
	// assignment against closeLocked's read of s.timer from the callback's
	// own goroutine. Assign under the lock instead — this is exactly what
	// -race caught here.
	timer := time.AfterFunc(duration, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closeLocked("")
	})
	s.mu.Lock()
	s.timer = timer
	s.mu.Unlock()

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// Get returns a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

// List returns every session's current status, most recently started first.
func (m *Manager) List() []Status {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Started.After(sessions[j].Started) })
	out := make([]Status, len(sessions))
	for i, s := range sessions {
		out[i] = s.Status()
	}
	return out
}

// Feed hands one captured frame to every active session whose target MAC it
// matches (as source or destination). Cheap when there are no active
// sessions — the common case — so it is safe to call on the hot packet path:
// one mutex-guarded copy of the session list, then a string compare each.
func (m *Manager) Feed(pkt live.Packet) {
	if len(pkt.Data) < 12 {
		return
	}
	dst := net.HardwareAddr(pkt.Data[0:6]).String()
	src := net.HardwareAddr(pkt.Data[6:12]).String()

	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()

	for _, s := range sessions {
		if s.MAC == dst || s.MAC == src {
			s.feed(pkt)
		}
	}
}
