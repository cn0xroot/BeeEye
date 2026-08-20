package analyze

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Store keeps recent analysis reports in memory.
//
// In memory rather than on disk deliberately: a report contains reconstructed
// sessions, plaintext credentials and carved file bodies — the most sensitive
// derivative of a capture there is. Keeping it only for the life of the process
// means an uploaded capture cannot quietly leave a copy of someone's password
// on the gateway's filesystem. The trade is that reports do not survive a
// restart, which is the right way round for this data.
type Store struct {
	mu      sync.RWMutex
	reports map[string]*Report
	order   []string
	limit   int
}

// NewStore returns a store keeping at most limit reports, oldest evicted first.
func NewStore(limit int) *Store {
	if limit <= 0 {
		limit = 10
	}
	return &Store{reports: map[string]*Report{}, limit: limit}
}

// Put files a report and returns its id.
func (s *Store) Put(r *Report) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.ID == "" {
		r.ID = newID()
	}
	s.reports[r.ID] = r
	s.order = append(s.order, r.ID)
	for len(s.order) > s.limit {
		delete(s.reports, s.order[0])
		s.order = s.order[1:]
	}
	return r.ID
}

// Get returns a report by id.
func (s *Store) Get(id string) (*Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reports[id]
	return r, ok
}

// File returns one carved file's bytes.
func (s *Store) File(reportID, fileID string) (*CarvedFile, bool) {
	rep, ok := s.Get(reportID)
	if !ok {
		return nil, false
	}
	for i := range rep.Files {
		if rep.Files[i].ID == fileID {
			return &rep.Files[i], true
		}
	}
	return nil, false
}

// Index is the light listing shown before a report is opened.
type Index struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	Uploaded    string `json:"uploaded"`
	Packets     int    `json:"packets"`
	Findings    int    `json:"findings"`
	Credentials int    `json:"credentials"`
	Files       int    `json:"files"`
}

// List returns the stored reports, newest first.
func (s *Store) List() []Index {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Index, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		r := s.reports[s.order[i]]
		if r == nil {
			continue
		}
		out = append(out, Index{
			ID: r.ID, Filename: r.Filename, Size: r.Size,
			Uploaded:    r.Uploaded.Format("2006-01-02 15:04:05"),
			Packets:     r.Summary.Packets,
			Findings:    len(r.Findings),
			Credentials: len(r.Credentials),
			Files:       len(r.Files),
		})
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not survivable in any meaningful way here,
		// and a predictable id would let one user guess another's report.
		panic("analyze: no entropy available for a report id: " + err.Error())
	}
	return hex.EncodeToString(b)
}
