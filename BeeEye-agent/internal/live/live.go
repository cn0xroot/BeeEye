// Package live provides the real-time packet capture sources feeding the
// Wireshark-style analyzer GUI (program.md §3.4 capture layer).
//
// Three sources implement the same Source interface so the GUI never knows
// which one is attached:
//
//  1. eBPF ringbuf  — future: kernel ≥5.8 + BTF, the production path (§3.4)
//  2. AF_PACKET     — now: a raw socket on the chosen interface, no CGO,
//     no libpcap; needs CAP_NET_RAW
//  3. simulator     — fallback: replays a synthetic home-network trace in
//     real time so the UI is exercisable without privileges
//
// Interface names are never hardcoded (F16); every source takes the name from
// configuration and records it on each packet (F17).
package live

import (
	"errors"
	"net"
	"time"
)

// Packet is one captured frame handed to the dissector. Data holds the raw
// bytes as they came off the wire, truncated to the snaplen.
type Packet struct {
	Index int64     // 1-based capture ordinal
	TS    time.Time // capture timestamp
	Iface string    // source interface name (F17)
	Data  []byte    // raw frame bytes (link layer first)
	// LinkType is a pcapfile.LinkEthernet/LinkRaw/LinkLinuxSLL/… value (see
	// that package's const block). Left at its zero value by every live
	// capture source (AF_PACKET, eBPF) — a physical or wireless NIC is
	// always genuine Ethernet framing, so there is nothing for them to set —
	// and dissect.Packet treats zero the same as LinkEthernet accordingly.
	// Only livefile (replaying a capture file, which can carry any LINKTYPE_
	// the tool that wrote it used) ever sets this to something else.
	LinkType uint32
	CapLen   int // bytes actually captured
	OrigLen  int // bytes on the wire before truncation
}

// Source is a running capture. Packets() is closed when the source stops.
type Source interface {
	Name() string           // source kind, e.g. "af_packet" / "simulator"
	Iface() string          // interface being captured
	Packets() <-chan Packet // stream of frames
	Stats() Stats           // live counters
	Close() error           // stop capturing and close the channel
}

// Stats are the counters the GUI status bar shows.
type Stats struct {
	Captured int64 `json:"captured"`
	Dropped  int64 `json:"dropped"`
	Bytes    int64 `json:"bytes"`
}

// ErrNoPermission is returned when the kernel refuses the raw socket — the
// caller is expected to fall back to the simulator rather than fail hard.
var ErrNoPermission = errors.New("raw capture requires CAP_NET_RAW (run as root, or: setcap cap_net_raw,cap_net_admin+ep ./BeeEye-gui)")

// DefaultSnapLen mirrors the usual Wireshark default.
const DefaultSnapLen = 262144

// IfaceInfo describes one capturable interface for the GUI's picker.
type IfaceInfo struct {
	Name  string   `json:"name"`
	Index int      `json:"index"`
	Up    bool     `json:"up"`
	MAC   string   `json:"mac"`
	Addrs []string `json:"addrs"`
	// Any marks the pseudo-interface that captures from every device at once.
	Any bool `json:"any,omitempty"`
}

// ListInterfaces returns every interface on this host. Down interfaces are
// reported too, so the UI can grey them out rather than silently hide them.
func ListInterfaces() ([]IfaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// The "any" pseudo-interface comes first, the way capture tools present it.
	// It is not a real device, so it carries no MAC or addresses.
	out := make([]IfaceInfo, 0, len(ifs)+1)
	out = append(out, IfaceInfo{Name: "any", Index: 0, Up: true, Any: true})

	for _, i := range ifs {
		info := IfaceInfo{Name: i.Name, Index: i.Index,
			Up:  i.Flags&net.FlagUp != 0,
			MAC: i.HardwareAddr.String()}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// Open returns the best available capture source for iface, falling back to
// the simulator when the raw socket is not permitted. The bool reports whether
// the capture is real (true) or simulated (false) — the UI labels it honestly
// instead of implying live data it does not have. The returned error is the
// reason for the fallback and is nil only when the capture is real.
func Open(iface string, snaplen int, promisc bool) (Source, bool, error) {
	if snaplen <= 0 {
		snaplen = DefaultSnapLen
	}
	src, err := OpenAFPacket(iface, snaplen, promisc)
	if err == nil {
		return src, true, nil
	}
	return OpenSimulated(iface), false, err
}
