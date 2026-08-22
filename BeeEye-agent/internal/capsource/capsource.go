// Package capsource picks the best real-packet capture source available on
// this host, trying each in order and falling back to the next when one
// cannot be used: eBPF ring buffer (lowest per-packet overhead, needs kernel
// ≥6.6 for TCX plus CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN) → AF_PACKET (works on
// any kernel with CAP_NET_RAW). If neither is available, Open returns an
// error rather than a synthetic source — see internal/live's own doc comment
// for why this project does not ship a simulated fallback.
//
// This lives above both internal/ebpf and internal/live rather than inside
// either of them: internal/ebpf already depends on internal/live for the
// Source/Packet/Stats types it adapts EVT_RAW_FRAME to, so folding this
// fallback chain into internal/live itself would create an import cycle.
//
// Only internal/livesource (the agent) calls this. internal/gui (the
// analyzer) deliberately calls live.Open directly instead — see the comment
// at that call site. TCX's own documentation says multiple independently
// attached programs on one interface all run; verified with bpftool prog
// show's run_cnt on this host's kernel, only the *first* one attached ever
// actually gets invoked, so a second eBPF attach to the same NIC "succeeds"
// (no error) but silently never sees a packet. Rather than build a
// self-check for that here (probe traffic, a timeout, a retry against
// AF_PACKET — real complexity for a kernel-version-specific quirk), the
// simpler fix is to only ever have one BeeEye process attaching eBPF to a
// given interface: the agent, which is the long-running process eBPF's
// lower overhead matters most for.
package capsource

import (
	"log"

	"BeeEye/internal/ebpf"
	"BeeEye/internal/live"
)

// Open tries eBPF first, then AF_PACKET — eBPF spliced in ahead of the
// two-tier degradation live.Open documents. The returned bool matches
// live.Open's contract (true only for a real capture); err is non-nil
// whenever neither source could be opened, matching live.Open.
func Open(iface string, snaplen int, promisc bool) (live.Source, bool, error) {
	if src, err := ebpf.OpenEBPF(iface); err == nil {
		return src, true, nil
	} else {
		log.Printf("capsource: eBPF unavailable on %s (%v) — falling back to AF_PACKET", iface, err)
	}
	return live.Open(iface, snaplen, promisc)
}
