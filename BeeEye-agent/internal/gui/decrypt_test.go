//go:build linux

package gui

import (
	"strings"
	"testing"

	"BeeEye/internal/tlspeek"
)

// TestDecryptorRecordAndRecent covers the buffering the API depends on: chunks
// are grouped per pid, capped, and returned newest-first — without needing a
// live capture or root.
func TestDecryptorRecordAndRecent(t *testing.T) {
	d := NewDecryptor()
	d.enabled = true // record() is a no-op unless enabled; skip the uprobe load

	for i := 0; i < decryptRingPerPID+50; i++ {
		d.record(&tlspeek.Event{PID: 100, Comm: "curl", Dir: tlspeek.DirRead,
			Data: []byte("chunk"), OrigLen: 5})
	}
	d.record(&tlspeek.Event{PID: 200, Comm: "python", Dir: tlspeek.DirWrite,
		Data: []byte("other"), OrigLen: 5})

	// The per-pid ring is capped.
	if got := len(d.byPID[100]); got != decryptRingPerPID {
		t.Errorf("pid 100 kept %d chunks, want cap %d", got, decryptRingPerPID)
	}

	// pid filter isolates a process.
	only := d.Recent(200, 100)
	if len(only) != 1 || only[0].Comm != "python" {
		t.Fatalf("Recent(200) = %+v, want one python chunk", only)
	}

	// No pid returns everything, newest first.
	all := d.Recent(0, 5)
	if len(all) != 5 {
		t.Errorf("Recent(0,5) returned %d, want 5", len(all))
	}
}

// TestEscapePreviewIsSafe checks that binary application data cannot inject
// control characters into the API response and is length-capped.
func TestEscapePreviewIsSafe(t *testing.T) {
	raw := []byte{0x00, 0x1b, 'h', 'i', '\n', 0x7f, 0xff}
	got := escapePreview(raw, previewMax)
	if strings.ContainsRune(got, 0x00) || strings.ContainsRune(got, 0x1b) {
		t.Errorf("preview leaked a control byte: %q", got)
	}
	if !strings.Contains(got, "hi\n") {
		t.Errorf("preview dropped printable text: %q", got)
	}
	if !strings.Contains(got, "\\x00") || !strings.Contains(got, "\\xff") {
		t.Errorf("preview did not escape non-printables: %q", got)
	}

	long := make([]byte, previewMax+500)
	for i := range long {
		long[i] = 'a'
	}
	if len(escapePreview(long, previewMax)) > previewMax {
		t.Error("preview exceeded the cap")
	}
}
