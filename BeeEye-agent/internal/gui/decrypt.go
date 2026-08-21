//go:build linux

package gui

import (
	"log"
	"sync"
	"time"

	"BeeEye/internal/tlspeek"
)

// decryptRingPerPID caps how many decrypted chunks are kept per process, so a
// busy process cannot evict everything else and memory stays bounded.
const decryptRingPerPID = 200

// rescanInterval controls how often start() re-walks /proc for libraries that
// were not mapped by any process yet at startup — a venv's own OpenSSL copy,
// an app installed after BeeEye started, a short-lived tool whose first run
// lands between scans. Attach is keyed by library path and idempotent, so a
// rescan only ever adds targets, never repeats work for one already probed.
const rescanInterval = 20 * time.Second

// pathScanDeadline bounds the one-time $PATH sweep (tlspeek.ScanPathBinaries)
// that runs after start(). It resolves every PATH entry's dynamic libraries
// via ldd, which on a large language-runtime bin/ directory can be thousands
// of files — generous because it runs in the background and nothing waits on
// it, but bounded because it must eventually give up on stragglers.
const pathScanDeadline = 20 * time.Second

// PlaintextChunk is one decrypted piece of a process's TLS traffic, shaped for
// the API. It carries the process so the UI can line it up with the packet
// list, which already attributes gateway-local flows to the same pid.
type PlaintextChunk struct {
	TimeMS    int64  `json:"ts_ms"`
	PID       int    `json:"pid"`
	Comm      string `json:"comm"`
	Direction string `json:"dir"` // "write" (sent) | "read" (received)
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
	Preview   string `json:"preview"` // UTF-8, control bytes escaped, capped
}

// previewMax bounds how much plaintext is shipped per chunk to the browser.
const previewMax = 4096

// Decryptor decrypts the gateway's own HTTPS by attaching uprobes to the
// OpenSSL libraries in use (tlspeek), and keeps the recent plaintext for the
// analyzer to show. It is the "HTTPS decryption on by default" path.
//
// Scope, unchanged from tlspeek: this reaches only libraries running on THIS
// host, and only dynamically linked ones whose symbols are present — the same
// set of processes procmap already attributes by name. Chrome-family browsers
// static-link a stripped BoringSSL and are covered by the SSLKEYLOGFILE route
// (scripts/tls-decrypt.sh), not here. See TLS-DECRYPT.md.
type Decryptor struct {
	mu       sync.Mutex
	peeker   *tlspeek.Peeker
	enabled  bool
	running  bool
	byPID    map[int][]PlaintextChunk
	attached int
	lastErr  string
	stop     chan struct{}
}

func NewDecryptor() *Decryptor {
	return &Decryptor{byPID: map[int][]PlaintextChunk{}}
}

// Enabled reports whether decryption is switched on.
func (d *Decryptor) Enabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

// Status is the decryptor state the UI shows.
type DecryptStatus struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Attached int    `json:"attached"` // number of libraries probed
	Error    string `json:"error,omitempty"`
}

func (d *Decryptor) Status() DecryptStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DecryptStatus{Enabled: d.enabled, Running: d.running, Attached: d.attached, Error: d.lastErr}
}

// Enable starts decryption: load the uprobe programs and attach them to every
// OpenSSL-family library currently in use. Best-effort — a kernel or
// permission problem is reported through Status, not returned as fatal, because
// the analyzer must keep working without decryption.
func (d *Decryptor) Enable() {
	d.mu.Lock()
	if d.enabled {
		d.mu.Unlock()
		return
	}
	d.enabled = true
	d.lastErr = ""
	d.mu.Unlock()
	d.start()
}

// Disable detaches the uprobes and drops the kept plaintext.
func (d *Decryptor) Disable() {
	d.mu.Lock()
	d.enabled = false
	peeker := d.peeker
	d.peeker = nil
	d.running = false
	d.attached = 0
	if d.stop != nil {
		close(d.stop)
		d.stop = nil
	}
	d.byPID = map[int][]PlaintextChunk{}
	d.mu.Unlock()
	if peeker != nil {
		peeker.Close()
	}
}

func (d *Decryptor) start() {
	peeker, err := tlspeek.Load()
	if err != nil {
		d.mu.Lock()
		d.lastErr = err.Error()
		d.running = false
		d.mu.Unlock()
		log.Printf("gui: HTTPS decryption unavailable: %v", err)
		return
	}

	libs, err := tlspeek.FindLibraries()
	if err != nil {
		d.mu.Lock()
		d.lastErr = err.Error()
		d.mu.Unlock()
	}
	stop := make(chan struct{})
	d.mu.Lock()
	d.peeker = peeker
	d.stop = stop
	d.mu.Unlock()

	// Attach to every library a decryption rule matches (OpenSSL, GnuTLS, …).
	// The rule table (tlspeek/rules.go) is the single place that list lives, so
	// this loop needs no change when a library family is added; libcrypto and
	// other non-matching objects are simply not returned as attach targets.
	// attachAll updates d.attached/d.running/d.lastErr on success; the "no
	// library yet" message below only fires when it found nothing to say.
	attached, _ := d.attachAll(peeker, libs)
	if attached == 0 {
		d.mu.Lock()
		if d.lastErr == "" {
			d.lastErr = "no OpenSSL-family library is currently in use to attach to"
		}
		d.mu.Unlock()
	}

	if attached > 0 {
		log.Printf("gui: HTTPS decryption on — probing %d OpenSSL librar%s", attached, plural(attached))
	}

	// Kept running even when attached == 0: a rescan can still pick up a
	// library that starts being used later, so there is nothing fatal about
	// today's system not doing any TLS yet.
	go d.drain(peeker.Events(), stop)
	go d.rescan(peeker, stop)
	go d.pathScan(peeker, stop)
}

// attachAll attaches every rule-matching library in libs (pid 0 — every
// process using it, present or future) and reconciles d's reported state
// against the peeker's own attached-target count, which is the single source
// of truth once several scans (runtime, PATH, periodic rescan) are all
// feeding the same peeker. Returns the total now attached and how many of
// those are new since this call started.
func (d *Decryptor) attachAll(peeker *tlspeek.Peeker, libs []tlspeek.Library) (total, gained int) {
	before := len(peeker.Targets())
	for _, lib := range libs {
		if lib.Family == "" {
			continue // no rule matches; not a decryption target
		}
		if err := peeker.Attach(lib.Path, 0); err != nil {
			log.Printf("gui: attach %s (%s): %v", lib.Path, lib.Family, err)
		}
	}
	total = len(peeker.Targets())
	gained = total - before

	d.mu.Lock()
	d.attached = total
	if total > 0 {
		d.running = true
		d.lastErr = ""
	}
	d.mu.Unlock()
	return total, gained
}

// rescan periodically re-walks /proc, attaching to any decryption-rule-
// matching library not already probed. It exists because start()'s own scan
// only sees processes running at that exact moment — a library first used by
// a process that starts afterwards (a venv's own OpenSSL, an app installed
// later, a short-lived tool that just hadn't run yet) would otherwise be
// invisible until BeeEye itself restarts.
func (d *Decryptor) rescan(peeker *tlspeek.Peeker, stop <-chan struct{}) {
	ticker := time.NewTicker(rescanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		libs, err := tlspeek.FindLibraries()
		if err != nil {
			continue
		}
		if _, gained := d.attachAll(peeker, libs); gained > 0 {
			log.Printf("gui: HTTPS decryption rescan found %d new librar%s", gained, plural(gained))
		}
	}
}

// pathScan runs once, asynchronously, after start() has already attached to
// whatever is running right now — see tlspeek.ScanPathBinaries for why this
// exists: a short-lived command (curl, any one-shot CLI tool) or a language
// runtime's own bundled library (a conda/venv Python's libssl.so, not the
// system one) that nothing has loaded yet would otherwise never be seen by
// the /proc-based scans, no matter how often they repeat. It does not block
// start() because resolving a large $PATH can take several seconds.
func (d *Decryptor) pathScan(peeker *tlspeek.Peeker, stop <-chan struct{}) {
	libs := tlspeek.ScanPathBinaries(pathScanDeadline)
	select {
	case <-stop:
		return // decryption was disabled while the scan was running
	default:
	}
	if _, gained := d.attachAll(peeker, libs); gained > 0 {
		log.Printf("gui: HTTPS decryption PATH scan found %d additional librar%s", gained, plural(gained))
	}
}

func (d *Decryptor) drain(events <-chan *tlspeek.Event, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			d.record(ev)
		}
	}
}

func (d *Decryptor) record(ev *tlspeek.Event) {
	chunk := PlaintextChunk{
		TimeMS:    time.Now().UnixMilli(),
		PID:       int(ev.PID),
		Comm:      ev.Comm,
		Direction: ev.Dir.String(),
		Bytes:     len(ev.Data),
		Truncated: ev.Truncated(),
		Preview:   escapePreview(ev.Data, previewMax),
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled {
		return
	}
	ring := append(d.byPID[chunk.PID], chunk)
	if len(ring) > decryptRingPerPID {
		ring = ring[len(ring)-decryptRingPerPID:]
	}
	d.byPID[chunk.PID] = ring
}

// Recent returns the most recent decrypted chunks. pid > 0 restricts to one
// process, which is how the packet detail shows the plaintext for the flow it
// is looking at.
func (d *Decryptor) Recent(pid, limit int) []PlaintextChunk {
	if limit <= 0 {
		limit = 100
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var all []PlaintextChunk
	if pid > 0 {
		all = append(all, d.byPID[pid]...)
	} else {
		for _, ring := range d.byPID {
			all = append(all, ring...)
		}
	}
	// Newest first.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if len(all) > limit {
		all = all[:limit]
	}
	return all
}

// Close releases everything.
func (d *Decryptor) Close() {
	d.Disable()
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// escapePreview keeps printable text and common whitespace, renders the rest as
// \xNN, and caps the length. Binary application data must not scramble the UI
// or bloat the response.
func escapePreview(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	out := make([]rune, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t' || c == '\r':
			out = append(out, rune(c))
		case c < 0x20 || c >= 0x7f:
			out = append(out, []rune{'\\', 'x', hexdig(c >> 4), hexdig(c & 0xf)}...)
		default:
			out = append(out, rune(c))
		}
	}
	return string(out)
}

func hexdig(v byte) rune {
	if v < 10 {
		return rune('0' + v)
	}
	return rune('a' + v - 10)
}
