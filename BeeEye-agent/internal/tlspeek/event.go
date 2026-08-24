//go:build linux

// Package tlspeek captures TLS plaintext by attaching uprobes to a userspace
// TLS library (F14; design and scope in TLS-DECRYPT.md).
//
// # What this can and cannot see
//
// A uprobe reaches only code running on this kernel. This package therefore
// captures the plaintext of processes on the gateway itself, and can never
// touch a camera, a lock or a phone — their TLS libraries run on their own
// hardware. It is the content-level companion to internal/procmap, which
// attributes exactly the same set of flows and honestly reports every other
// flow as "not this host".
//
// # Privacy
//
// This is the first part of BeeEye that reads application content rather than
// metadata. It is off unless a caller explicitly names a target, there is no
// "attach to everything" entry point, and Event.Data is capped so a single
// large transfer cannot be reconstructed wholesale from the ring buffer.
package tlspeek

import (
	"encoding/binary"
	"fmt"
)

// Layout of struct BeeEye_tls_event in bpf/BeeEye_tls_events.h. Changing
// either side without the other is caught by TestTLSEventLayoutMatchesBTF,
// which reads the compiled object's own BTF rather than trusting this comment.
const (
	// ChunkMax is the room for plaintext in one record.
	ChunkMax = 2048
	// ChunkCap is the most bytes the kernel ever copies into it — one less
	// than ChunkMax, because the verifier bound is a power-of-two mask.
	ChunkCap = ChunkMax - 1

	commLen = 16

	offTS      = 0
	offPID     = 8
	offTID     = 12
	offLen     = 16
	offOrigLen = 20
	offDir     = 24
	offComm    = 28
	offData    = 44

	// EventSize is the on-wire size of one record, including the tail
	// padding the compiler adds to keep the struct 8-byte aligned.
	EventSize = 2096
)

// Direction reports which side of the encryption boundary a chunk came from.
type Direction uint8

const (
	// DirWrite is SSL_write: plaintext the process is about to send.
	DirWrite Direction = 0
	// DirRead is SSL_read: plaintext the process just received.
	DirRead Direction = 1
	// DirKeylog is a TLS 1.2 master-secret record — see masterkey.go's
	// KeylogLine. Data is not application content for this direction.
	DirKeylog Direction = 2
)

func (d Direction) String() string {
	switch d {
	case DirWrite:
		return "write"
	case DirRead:
		return "read"
	case DirKeylog:
		return "keylog"
	}
	return "unknown"
}

// Event is one captured plaintext chunk.
type Event struct {
	TimeNS  uint64
	PID     uint32
	TID     uint32
	Dir     Direction
	Comm    string
	Data    []byte
	OrigLen int // bytes the call handled, before the ChunkCap cap
}

// Truncated reports whether the process handled more than was captured. The UI
// must say so rather than presenting a clipped body as the whole message.
func (e *Event) Truncated() bool { return e.OrigLen > len(e.Data) }

// ParseEvent decodes one ringbuf record. Data is copied, because the ringbuf
// sample memory is reused the moment the reader advances.
func ParseEvent(rec []byte) (*Event, error) {
	if len(rec) < EventSize {
		return nil, fmt.Errorf("tlspeek: short record: %d bytes, want %d", len(rec), EventSize)
	}
	n := int(int32(binary.LittleEndian.Uint32(rec[offLen:])))
	if n < 0 || n > ChunkCap {
		return nil, fmt.Errorf("tlspeek: implausible chunk length %d", n)
	}
	ev := &Event{
		TimeNS:  binary.LittleEndian.Uint64(rec[offTS:]),
		PID:     binary.LittleEndian.Uint32(rec[offPID:]),
		TID:     binary.LittleEndian.Uint32(rec[offTID:]),
		OrigLen: int(int32(binary.LittleEndian.Uint32(rec[offOrigLen:]))),
		Dir:     Direction(rec[offDir]),
		Comm:    cstring(rec[offComm : offComm+commLen]),
		Data:    append([]byte(nil), rec[offData:offData+n]...),
	}
	return ev, nil
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
