/* 蜂眼 BeeEye — the kernel↔userspace event contract (program.md §3.4.2/§3.4.4).
 *
 * This header is the single source of truth for the ringbuf record layout. The
 * Go side mirrors it field-for-field in internal/ebpf/event.go; if you change
 * anything here, change it there and re-run `go test ./internal/ebpf/...`,
 * which asserts the two agree on size and offsets.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef __BeeEye_EVENTS_H__
#define __BeeEye_EVENTS_H__

/* Bytes of L4 payload shipped per event. Large enough to hold a full DNS
 * message and the SNI/cipher-list region of a real-world TLS ClientHello
 * (Chrome's run ~500B with GREASE and padding); anything past this is not
 * needed for SNI/ALPN/JA3 extraction (§3.4.3). */
#define PAYLOAD_MAX 512

/* Transport numbers, spelled with a BE_ prefix so the names can never collide
 * with an enum of the same name emitted into vmlinux.h by bpftool. */
#define BE_IPPROTO_TCP 6
#define BE_IPPROTO_UDP 17

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#define AF_INET_ 2
#define AF_INET6_ 10

/* Direction relative to the interface the program is attached to. */
enum BeeEye_dir {
	DIR_INGRESS = 0, /* arriving at the gateway from the LAN device */
	DIR_EGRESS = 1,  /* leaving the gateway toward the LAN device */
};

/* Event kinds. Full-fidelity kinds are reported every time they occur;
 * FLOW_SNAPSHOT is the aggregated path (§3.4.4). */
enum BeeEye_evt {
	EVT_FLOW_SNAPSHOT = 1, /* periodic per-flow statistics roll-up */
	EVT_FLOW_NEW = 2,      /* first packet of a flow from a lock/camera */
	EVT_DNS = 3,           /* plaintext DNS or mDNS message (F21) */
	EVT_TLS_CLIENT_HELLO = 4, /* SNI / ALPN / cipher list source (F3) */
	EVT_TLS_SERVER_HELLO = 5, /* JA3S source (F3) */
	EVT_NEWDEV = 6,        /* MAC seen for the first time (F8) */
	EVT_ARP = 7,           /* lateral-movement signal (F34/F36) */
	EVT_SSDP = 8,          /* discovery broadcast → fingerprinting (F1) */
	EVT_DHCP = 9,          /* Option 55/60 fingerprint (F1, §3.5.2) */
};

/* Device categories. Userspace writes these back into device_stats after
 * fingerprinting (§3.5.2 step 4); the kernel reads them to pick the reporting
 * tier (§3.5.3). Values must stay in sync with model.DeviceCategory. */
enum BeeEye_category {
	CAT_UNKNOWN = 0,
	CAT_CAMERA = 1,
	CAT_LOCK = 2,
	CAT_NAS = 3,
	CAT_ROUTER = 4,
	CAT_TV = 5,
	CAT_PHONE = 6,
	CAT_LAPTOP = 7,
	CAT_FRIDGE = 8,
	CAT_SPEAKER = 9,
};

/* Slots in the cfg array map. Everything tunable comes from config.yaml —
 * no thresholds are baked into the bytecode (§3.11.3 "阈值可在配置中调整"). */
enum BeeEye_cfg_slot {
	CFG_FLOW_INTERVAL_NS = 0,      /* flush interval for ordinary devices */
	CFG_SENSITIVE_INTERVAL_NS = 1, /* flush interval for lock/camera */
	CFG_SLOT__MAX = 8,
};

/* One ringbuf record. Field order is chosen so every member lands on its
 * natural alignment and the struct needs no implicit padding — that is what
 * lets Go decode it with a plain binary.Read of the mirrored struct. */
struct BeeEye_event {
	__u64 ts;            /* bpf_ktime_get_ns at capture */
	__u64 flow_pkts;     /* FLOW_* kinds: packets so far in this flow */
	__u64 flow_bytes;    /* FLOW_* kinds: bytes so far in this flow */
	__u64 flow_first_ts; /* FLOW_* kinds: flow start */

	__u32 ifindex;     /* source interface (F17, §3.4.5) */
	__u32 pkt_len;     /* skb->len */
	__u32 payload_len; /* valid bytes in payload[] */

	__u16 eth_proto; /* host-order EtherType after VLAN unwrapping */
	__u16 vlan;      /* innermost VLAN id, 0 if untagged */
	__u16 sport;
	__u16 dport;

	__u8 smac[6];
	__u8 dmac[6];
	__u8 saddr[16]; /* IPv4 occupies the first 4 bytes; see family */
	__u8 daddr[16];

	__u8 kind;      /* enum BeeEye_evt */
	__u8 dir;       /* enum BeeEye_dir */
	__u8 proto;     /* IP protocol number */
	__u8 family;    /* AF_INET_ / AF_INET6_ */
	__u8 category;  /* enum BeeEye_category, as known at capture time */
	__u8 tcp_flags; /* TCP only */
	__u8 ttl;       /* IPv4 TTL / IPv6 hop limit */
	__u8 _pad;

	__u8 payload[PAYLOAD_MAX];
};

#endif /* __BeeEye_EVENTS_H__ */
