// 蜂眼 BeeEye — kernel-side capture program (program.md §3.4).
//
// A single CO-RE TC classifier, attached to ingress AND egress of every
// interface named in config.yaml (§3.4.5). The same bytecode serves every
// interface; the source ifindex travels inside the flow key so one flow table
// covers all NICs without per-interface maps (§3.4.5, F16/F17).
//
// What runs here (kernel) vs there (userspace) follows §3.4.3: the kernel only
// locates and copies bounded raw field bytes — no string building, no MD5.
// JA3 computation, DNS name decoding and protocol identification all happen in
// the Go agent, where the verifier's limits do not apply.
//
// Reporting policy (§3.4.4):
//   - TLS ClientHello / DNS / new MAC  → reported in full, every time
//   - lock & camera category devices   → every flow reported (§3.5.3)
//   - everything else                  → aggregated in an LRU flow table and
//                                        flushed as a snapshot every 5s
//
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#include "BeeEye_events.h"

/* ---------------------------------------------------------------- maps */

/* Event channel to userspace. RINGBUF is the 5.8+ recommendation (§3.2).
 * 16 MiB, not 4: EVT_RAW_FRAME (raw-frame mode) grew struct BeeEye_event to
 * ~1.6 KiB per record (PAYLOAD_MAX now covers a full Ethernet frame, not just
 * a protocol header), so the old 4 MiB would buffer noticeably fewer packets
 * during a userspace stall. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 << 20); /* 16 MiB */
} events SEC(".maps");

/* device MAC → tiering state. Userspace writes `category` back after
 * fingerprinting (§3.5.2 step 4) so the tiering decision happens in-kernel. */
struct device_key {
	__u8 mac[6];
	__u8 _pad[2];
};

struct device_stat {
	__u64 tx_bytes, rx_bytes;
	__u64 conn_count;
	__u64 last_seen;
	__u8 category; /* see enum BeeEye_category in BeeEye_events.h */
	__u8 _pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct device_key);
	__type(value, struct device_stat);
} device_stats SEC(".maps");

/* Connection flow table. LRU so a scan storm cannot grow it without bound
 * (§3.4.2). ifindex is part of the key: same table, many NICs (§3.4.5). */
struct flow_key {
	__u32 ifindex;
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport, dport;
	__u8 proto;
	__u8 family;
	__u8 _pad[2];
};

struct flow_stat {
	__u64 pkts, bytes;
	__u64 first_ts, last_ts, last_report_ts;
	__u8 smac[6];
	__u8 is_tls;
	__u8 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_stat);
} flows SEC(".maps");

/* Runtime knobs, written by userspace from config.yaml — nothing tunable is
 * baked into the bytecode. Index: enum BeeEye_cfg_slot. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_SLOT__MAX);
	__type(key, __u32);
	__type(value, __u64);
} cfg SEC(".maps");

/* Per-CPU scratch for the event being built — a ~600 byte struct blows the
 * 512 byte BPF stack limit, so it never lives on the stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct BeeEye_event);
} scratch SEC(".maps");

/* ------------------------------------------------------------- helpers */

static __always_inline __u64 cfg_get(__u32 slot, __u64 dflt)
{
	__u64 *v = bpf_map_lookup_elem(&cfg, &slot);
	if (!v || *v == 0)
		return dflt;
	return *v;
}

/* load_payload copies up to PAYLOAD_MAX bytes of L4 payload into the event.
 *
 * bpf_skb_load_bytes needs a compile-time constant length for the verifier to
 * prove the write is in bounds, so we step down through a cascade of constants
 * rather than passing a runtime length. Worst case this truncates to the next
 * smaller step — acceptable, because every consumer (DNS name, ClientHello
 * SNI/JA3) re-validates its own bounds in userspace anyway.
 */
static __always_inline __u32 load_payload(struct __sk_buff *skb, __u32 off,
					  __u8 *dst, __u32 avail)
{
#define TRY(n)                                                       \
	if (avail >= (n)) {                                          \
		if (bpf_skb_load_bytes(skb, off, dst, (n)) == 0)     \
			return (n);                                  \
		return 0;                                            \
	}
	TRY(PAYLOAD_MAX)
	TRY(384)
	TRY(256)
	TRY(192)
	TRY(128)
	TRY(96)
	TRY(64)
	TRY(48)
	TRY(32)
	TRY(16)
	TRY(8)
#undef TRY
	return 0;
}

static __always_inline struct BeeEye_event *scratch_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&scratch, &zero);
}

/* emit copies the staged event into the ringbuf. Userspace reads payload_len
 * to know how many of the payload bytes are meaningful; the rest of the
 * reservation is shipped regardless (a constant reservation size is what
 * bpf_ringbuf_reserve needs), so a 40-byte DNS query still costs a full
 * record — bounded, and the ringbuf is 16 MiB.
 *
 * The copy itself is a manually unrolled 8-byte word loop rather than one
 * __builtin_memcpy(out, ev, sizeof(*ev)): clang for the BPF target refuses to
 * inline-expand a memcpy this large (sizeof(struct BeeEye_event) grew past
 * whatever its threshold is once PAYLOAD_MAX covers a whole Ethernet frame —
 * see BeeEye_events.h) and there is no libc memcpy symbol to call out to.
 * A fully unrolled, fixed-trip-count word loop compiles to plain sequential
 * loads/stores instead, which has never had this limit. */
_Static_assert(sizeof(struct BeeEye_event) % 8 == 0,
	       "emit()'s word-copy loop assumes 8-byte alignment");

static __always_inline void emit(struct BeeEye_event *ev)
{
	struct BeeEye_event *out = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!out)
		return;
	const __u64 *src = (const __u64 *)ev;
	__u64 *dst = (__u64 *)out;
#pragma unroll
	for (__u32 i = 0; i < sizeof(*ev) / 8; i++)
		dst[i] = src[i];
	bpf_ringbuf_submit(out, 0);
}

/* track_device updates the per-MAC asset row and returns its category, or
 * emits a NEWDEV event the first time a MAC is seen (F8). */
static __always_inline __u8 track_device(const __u8 *mac, __u64 now, int egress,
					 __u32 len, int *is_new)
{
	struct device_key k = {};
	__builtin_memcpy(k.mac, mac, 6);

	struct device_stat *d = bpf_map_lookup_elem(&device_stats, &k);
	if (!d) {
		struct device_stat init = {};
		init.last_seen = now;
		if (egress)
			init.rx_bytes = len; /* toward the device */
		else
			init.tx_bytes = len; /* from the device */
		bpf_map_update_elem(&device_stats, &k, &init, BPF_NOEXIST);
		*is_new = 1;
		return CAT_UNKNOWN;
	}
	if (egress)
		__sync_fetch_and_add(&d->rx_bytes, len);
	else
		__sync_fetch_and_add(&d->tx_bytes, len);
	d->last_seen = now;
	*is_new = 0;
	return d->category;
}

/* ------------------------------------------------------------ main path */

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_ARP 0x0806

static __always_inline int handle(struct __sk_buff *skb, __u8 dir)
{
	struct BeeEye_event *ev = scratch_event();
	if (!ev)
		return TC_ACT_OK;
	/* Only the header needs zeroing, not the 1536-byte payload array: every
	 * path that emits an event either sets payload_len itself (a field
	 * inside this zeroed header region) via load_payload's return value, or
	 * leaves it at this zero, and every reader trusts payload_len rather
	 * than assuming the array is clean past it. Zeroing the whole struct
	 * hits the same "clang won't inline a memset this large" wall emit()'s
	 * comment explains for memcpy. */
	__builtin_memset(ev, 0, __builtin_offsetof(struct BeeEye_event, payload));

	__u64 now = bpf_ktime_get_ns();
	__u32 off = 0;

	/* --- L2 ------------------------------------------------------- */
	if (bpf_skb_load_bytes(skb, 0, ev->dmac, 6) < 0)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, 6, ev->smac, 6) < 0)
		return TC_ACT_OK;
	__u16 h_proto;
	if (bpf_skb_load_bytes(skb, 12, &h_proto, 2) < 0)
		return TC_ACT_OK;
	h_proto = bpf_ntohs(h_proto);
	off = ETH_HLEN;

	/* VLAN tags: walk at most two (QinQ) so the loop is bounded. */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto != ETH_P_8021Q && h_proto != ETH_P_8021AD)
			break;
		__u16 tci, inner;
		if (bpf_skb_load_bytes(skb, off, &tci, 2) < 0)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, off + 2, &inner, 2) < 0)
			return TC_ACT_OK;
		ev->vlan = bpf_ntohs(tci) & 0x0FFF;
		h_proto = bpf_ntohs(inner);
		off += 4;
	}

	ev->ifindex = skb->ifindex;
	ev->ts = now;
	ev->dir = dir;
	ev->pkt_len = skb->len;
	ev->eth_proto = h_proto;

	/* Raw-frame mode (internal/ebpf/source.go): mirror the whole frame,
	 * verbatim from byte 0 (not `off`, which has already walked past
	 * L2/VLAN), and skip every protocol-specific branch below entirely —
	 * userspace's dissector does that work itself when replaying these
	 * frames, exactly as it does for AF_PACKET. This intentionally comes
	 * before track_device: in this mode userspace re-derives device
	 * identity from the raw frame the same way the AF_PACKET path does,
	 * so the in-kernel device_stats/NEWDEV bookkeeping below is not this
	 * mode's job. */
	if (cfg_get(CFG_RAW_FRAME_MODE, 0)) {
		ev->kind = EVT_RAW_FRAME;
		/* load_payload's cascade steps down through a handful of widely
		 * spaced constants (1536/384/256/.../8), which is fine for the
		 * selective kinds below — a short DNS/TLS payload only ever needs
		 * its first few hundred bytes. It is wrong here: a 63-byte frame
		 * landing between the 48 and 64 steps would lose 15 bytes for no
		 * reason, which is exactly the gap between "SNI extraction" and
		 * "a faithful frame mirror". A clamped, exact-length load — the
		 * verifier can prove this one in-bounds because len's value range
		 * is tracked down to [0, PAYLOAD_MAX] by the two comparisons
		 * below — copies precisely min(skb->len, PAYLOAD_MAX) instead. */
		__u32 len = skb->len;
		if (len > PAYLOAD_MAX)
			len = PAYLOAD_MAX;
		if (len > 0 && bpf_skb_load_bytes(skb, 0, ev->payload, len) == 0)
			ev->payload_len = len;
		emit(ev);
		return TC_ACT_OK;
	}

	/* The device is whichever side is on the LAN: on ingress the source
	 * MAC is the device, on egress the destination MAC is (§3.4.1 note on
	 * mounting the LAN-side interface to keep device granularity). */
	const __u8 *devmac = (dir == DIR_EGRESS) ? ev->dmac : ev->smac;
	int is_new = 0;
	__u8 category = track_device(devmac, now, dir == DIR_EGRESS, skb->len, &is_new);
	ev->category = category;

	if (is_new) {
		ev->kind = EVT_NEWDEV;
		emit(ev);
		ev->kind = 0;
	}

	if (h_proto == ETH_P_ARP) {
		/* ARP is how lateral scanning announces itself (F34/F36); it is
		 * cheap and rare enough to always report. */
		ev->kind = EVT_ARP;
		ev->family = 0;
		ev->payload_len = load_payload(skb, off, ev->payload,
					       skb->len > off ? skb->len - off : 0);
		emit(ev);
		return TC_ACT_OK;
	}

	/* --- L3 ------------------------------------------------------- */
	__u8 proto = 0;
	__u32 l4off = 0;

	if (h_proto == ETH_P_IP) {
		struct {
			__u8 ver_ihl;
			__u8 tos;
			__u16 tot_len;
			__u16 id;
			__u16 frag_off;
			__u8 ttl;
			__u8 proto;
			__u16 check;
			__u32 saddr;
			__u32 daddr;
		} ip4;
		if (bpf_skb_load_bytes(skb, off, &ip4, sizeof(ip4)) < 0)
			return TC_ACT_OK;
		__u32 ihl = (ip4.ver_ihl & 0x0F) * 4;
		if (ihl < 20 || ihl > 60)
			return TC_ACT_OK;
		ev->family = AF_INET_;
		/* IPv4 lives in the first 4 bytes of the 16-byte slot; the Go
		 * side reads family to know how many bytes are meaningful. */
		__builtin_memcpy(ev->saddr, &ip4.saddr, 4);
		__builtin_memcpy(ev->daddr, &ip4.daddr, 4);
		ev->ttl = ip4.ttl;
		proto = ip4.proto;
		/* Fragments past the first carry no L4 header — count and go. */
		if (bpf_ntohs(ip4.frag_off) & 0x1FFF)
			proto = 0;
		l4off = off + ihl;
	} else if (h_proto == ETH_P_IPV6) {
		struct {
			__u32 ver_tc_fl;
			__u16 payload_len;
			__u8 nexthdr;
			__u8 hop_limit;
			__u8 saddr[16];
			__u8 daddr[16];
		} ip6;
		if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)) < 0)
			return TC_ACT_OK;
		ev->family = AF_INET6_;
		__builtin_memcpy(ev->saddr, ip6.saddr, 16);
		__builtin_memcpy(ev->daddr, ip6.daddr, 16);
		ev->ttl = ip6.hop_limit;
		proto = ip6.nexthdr; /* extension headers are left to userspace */
		l4off = off + 40;
	} else {
		return TC_ACT_OK; /* not IP — nothing this system models */
	}
	ev->proto = proto;

	/* --- L4 ------------------------------------------------------- */
	__u32 payoff = 0;
	if (proto == BE_IPPROTO_TCP) {
		struct {
			__u16 sport, dport;
			__u32 seq, ack;
			__u8 off_res;
			__u8 flags;
			__u16 win, csum, urg;
		} tcp;
		if (bpf_skb_load_bytes(skb, l4off, &tcp, sizeof(tcp)) < 0)
			return TC_ACT_OK;
		ev->sport = bpf_ntohs(tcp.sport);
		ev->dport = bpf_ntohs(tcp.dport);
		ev->tcp_flags = tcp.flags;
		__u32 doff = (tcp.off_res >> 4) * 4;
		if (doff < 20 || doff > 60)
			return TC_ACT_OK;
		payoff = l4off + doff;
	} else if (proto == BE_IPPROTO_UDP) {
		struct {
			__u16 sport, dport, len, csum;
		} udp;
		if (bpf_skb_load_bytes(skb, l4off, &udp, sizeof(udp)) < 0)
			return TC_ACT_OK;
		ev->sport = bpf_ntohs(udp.sport);
		ev->dport = bpf_ntohs(udp.dport);
		payoff = l4off + 8;
	} else {
		payoff = l4off; /* ICMP and friends: statistics only */
	}

	__u32 avail = skb->len > payoff ? skb->len - payoff : 0;

	/* --- full-fidelity events (§3.4.4: handshake packets always report) - */
	__u8 first = 0;
	if (avail > 0)
		bpf_skb_load_bytes(skb, payoff, &first, 1);

	int always_report = 0;

	if (proto == BE_IPPROTO_UDP && (ev->sport == 53 || ev->dport == 53 ||
				     ev->sport == 5353 || ev->dport == 5353)) {
		/* Plaintext DNS / mDNS — the domain↔IP↔device join (§3.4.6, F21).
		 * The wire bytes go up verbatim; QNAME decoding is userspace's. */
		ev->kind = EVT_DNS;
		always_report = 1;
	} else if (proto == BE_IPPROTO_TCP && avail >= 6 && first == 0x16) {
		/* TLS record, handshake type. ClientHello = 0x01, ServerHello =
		 * 0x02. We ship the record prefix; SNI/ALPN/cipher-list parsing
		 * and the JA3 hash are userspace's job (§3.4.3). */
		__u8 hs = 0;
		bpf_skb_load_bytes(skb, payoff + 5, &hs, 1);
		if (hs == 0x01 || hs == 0x02) {
			ev->kind = hs == 0x01 ? EVT_TLS_CLIENT_HELLO
					      : EVT_TLS_SERVER_HELLO;
			always_report = 1;
		}
	} else if (proto == BE_IPPROTO_UDP &&
		   (ev->dport == 1900 || ev->sport == 1900)) {
		ev->kind = EVT_SSDP; /* device discovery → fingerprinting (F1) */
		always_report = 1;
	} else if (proto == BE_IPPROTO_UDP &&
		   (ev->dport == 67 || ev->dport == 68)) {
		ev->kind = EVT_DHCP; /* Option 55/60 fingerprint (F1, §3.5.2) */
		always_report = 1;
	}

	if (always_report) {
		ev->payload_len = load_payload(skb, payoff, ev->payload, avail);
		emit(ev);
		return TC_ACT_OK;
	}

	/* --- aggregated path (§3.4.4) --------------------------------- */
	struct flow_key fk = {};
	fk.ifindex = skb->ifindex;
	fk.family = ev->family;
	fk.proto = proto;
	fk.sport = ev->sport;
	fk.dport = ev->dport;
	__builtin_memcpy(fk.saddr, ev->saddr, 16);
	__builtin_memcpy(fk.daddr, ev->daddr, 16);

	struct flow_stat *fs = bpf_map_lookup_elem(&flows, &fk);
	if (!fs) {
		struct flow_stat init = {};
		init.pkts = 1;
		init.bytes = skb->len;
		init.first_ts = now;
		init.last_ts = now;
		init.last_report_ts = now;
		__builtin_memcpy(init.smac, ev->smac, 6);
		bpf_map_update_elem(&flows, &fk, &init, BPF_ANY);

		/* A brand-new flow from a lock or camera is reported the moment
		 * it appears — those categories get full connection logging
		 * regardless of volume (§3.5.3, F5). */
		if (category == CAT_LOCK || category == CAT_CAMERA) {
			ev->kind = EVT_FLOW_NEW;
			ev->flow_pkts = 1;
			ev->flow_bytes = skb->len;
			emit(ev);
		}
		return TC_ACT_OK;
	}

	__sync_fetch_and_add(&fs->pkts, 1);
	__sync_fetch_and_add(&fs->bytes, skb->len);
	fs->last_ts = now;

	/* Periodic snapshot instead of per-packet reporting. High-sensitivity
	 * categories flush faster; everything else uses the configured interval. */
	__u64 interval = cfg_get(CFG_FLOW_INTERVAL_NS, 5000000000ULL); /* 5s */
	if (category == CAT_LOCK || category == CAT_CAMERA)
		interval = cfg_get(CFG_SENSITIVE_INTERVAL_NS, 1000000000ULL); /* 1s */

	if (now - fs->last_report_ts >= interval) {
		fs->last_report_ts = now;
		ev->kind = EVT_FLOW_SNAPSHOT;
		ev->flow_pkts = fs->pkts;
		ev->flow_bytes = fs->bytes;
		ev->flow_first_ts = fs->first_ts;
		emit(ev);
	}
	return TC_ACT_OK;
}

SEC("tc")
int BeeEye_tc_ingress(struct __sk_buff *skb)
{
	return handle(skb, DIR_INGRESS);
}

SEC("tc")
int BeeEye_tc_egress(struct __sk_buff *skb)
{
	return handle(skb, DIR_EGRESS);
}
