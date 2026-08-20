package mitm

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// maxBodyCapture bounds how much of a request/response body is kept per
// exchange — enough to read a JSON payload or an HTML page, not enough for a
// video download to fill memory. The wire relay to the real client is never
// truncated by this; only what gets recorded for the UI is.
const maxBodyCapture = 256 << 10 // 256KiB

// Exchange is one decrypted HTTP request/response pair, the MITM proxy's
// equivalent of a captured packet. It is intentionally created in memory
// only, exactly like internal/analyze.Store's pcap reports and for the same
// reason: this is the single most sensitive data BeeEye ever handles
// (a device's plaintext traffic, potentially including credentials), so
// nothing here survives a restart or lands on disk.
type Exchange struct {
	ID         string      `json:"id"`
	Time       time.Time   `json:"time"`
	ClientAddr string      `json:"client_addr"`
	Method     string      `json:"method"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	ReqHeaders http.Header `json:"req_headers"`
	ReqBody    []byte      `json:"-"`
	ReqTrunc   bool        `json:"req_truncated"`

	StatusCode  int         `json:"status_code"`
	RespHeaders http.Header `json:"resp_headers"`
	RespBody    []byte      `json:"-"`
	RespTrunc   bool        `json:"resp_truncated"`

	Err string `json:"error,omitempty"`
}

// Summary is the row shape a list view needs — no bodies, no full headers.
type Summary struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	ClientAddr string    `json:"client_addr"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	ReqBytes   int       `json:"req_bytes"`
	RespBytes  int       `json:"resp_bytes"`
	Err        string    `json:"error,omitempty"`
}

func (e *Exchange) Summary() Summary {
	return Summary{
		ID: e.ID, Time: e.Time, ClientAddr: e.ClientAddr,
		Method: e.Method, Host: e.Host, Path: e.Path,
		StatusCode: e.StatusCode, ReqBytes: len(e.ReqBody), RespBytes: len(e.RespBody),
		Err: e.Err,
	}
}

// exchangeStore keeps the most recent decrypted exchanges, oldest evicted
// first — same ring shape as analyze.Store.
type exchangeStore struct {
	mu    sync.RWMutex
	byID  map[string]*Exchange
	order []string
	limit int
}

func newExchangeStore(limit int) *exchangeStore {
	if limit <= 0 {
		limit = 500
	}
	return &exchangeStore{byID: map[string]*Exchange{}, limit: limit}
}

func (s *exchangeStore) put(e *Exchange) {
	if e.ID == "" {
		e.ID = newID()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[e.ID] = e
	s.order = append(s.order, e.ID)
	for len(s.order) > s.limit {
		delete(s.byID, s.order[0])
		s.order = s.order[1:]
	}
}

func (s *exchangeStore) get(id string) (*Exchange, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byID[id]
	return e, ok
}

// list returns the most recent n summaries, newest first.
func (s *exchangeStore) list(n int) []Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n > len(s.order) {
		n = len(s.order)
	}
	out := make([]Summary, 0, n)
	for i := len(s.order) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, s.byID[s.order[i]].Summary())
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
