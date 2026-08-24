/* 蜂眼 BeeEye — the TLS-plaintext uprobe event contract.
 *
 * Companion to BeeEye_events.h, kept separate because it belongs to a
 * different program with a different attach point and a different threat
 * model: this one reads application *content*, not packet metadata.
 *
 * The Go side mirrors this layout field-for-field in
 * internal/tlspeek/event.go, and TestTLSEventLayoutMatchesBTF asserts the two
 * agree on size and offsets by reading the compiled object's own BTF.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef __BeeEye_TLS_EVENTS_H__
#define __BeeEye_TLS_EVENTS_H__

/* Plaintext bytes shipped per event.
 *
 * A single SSL_write is not a single TCP segment and is not bounded by the
 * MTU — a large POST body arrives as one call. Capping here bounds both the
 * ringbuf record and the per-call copy cost; the full length is reported in
 * `orig_len` so the UI can say "truncated" rather than silently lying about
 * how much was sent. */
#define TLS_CHUNK_MAX 2048

/* The most bytes actually copied. One less than the record's room, and one
 * less than a power of two, because that is what lets the verifier prove the
 * copy is in bounds: `len &= TLS_CHUNK_CAP` bounds len to [0, 2047] as a
 * property of the value, whereas an `if (len > N)` compare alone is not
 * enough once the compiler has widened len to 32 bits. */
#define TLS_CHUNK_CAP (TLS_CHUNK_MAX - 1)

/* Room for the comm string, matching TASK_COMM_LEN. */
#define TLS_COMM_LEN 16

/* Which side of the library call the plaintext came from. */
enum BeeEye_tls_dir {
	TLS_DIR_WRITE = 0,  /* SSL_write: plaintext on its way out, pre-encryption */
	TLS_DIR_READ = 1,   /* SSL_read: plaintext after decryption */
	/* TLS 1.2 master-secret keylog record — see BeeEye_ssl_offsets below.
	 * data[] carries a fixed 88-byte payload, not application content:
	 *   [0:32)  client_random (SSL3_RANDOM_SIZE)
	 *   [32:40) master_key_length as little-endian u64 (always 48 when
	 *           this fires — see the length check in the probe)
	 *   [40:88) master_key (SSL3_MASTER_SECRET_SIZE, zero-padded to 48
	 *           if a shorter length were ever seen — it never is today)
	 * len/orig_len are both 88 for this direction. */
	TLS_DIR_KEYLOG = 2,
};

/* Per-process struct-field offsets needed to read the TLS 1.2 master secret
 * out of an `SSL *`, computed once in userspace (internal/tlspeek/masterkey.go)
 * from the exact OpenSSL version string embedded in the library — see that
 * file's doc comment for why this can't be CO-RE (no BTF in release .so
 * builds) and why it's scoped to TLS 1.2 (a TLS 1.3 secret's length depends on
 * the negotiated cipher's hash, which needs a second lookup this table does
 * not yet carry). All offsets are relative to the `SSL *` uprobe argument
 * except master_key_len_off/master_key_off, which are relative to the
 * `SSL_SESSION *` read from session_off.
 */
struct BeeEye_ssl_offsets {
	__u32 session_off;        /* offsetof(struct ssl_st, session) */
	__u32 client_random_off;  /* offsetof(struct ssl_st, s3.client_random) */
	__u32 master_key_len_off; /* offsetof(struct ssl_session_st, master_key_length) */
	__u32 master_key_off;     /* offsetof(struct ssl_session_st, master_key) */
};

/* One captured plaintext chunk.
 *
 * Fixed size rather than variable: bpf_ringbuf_reserve needs a compile-time
 * constant, and a fixed record keeps the Go decoder a plain offset read with
 * no length arithmetic to get wrong. */
struct BeeEye_tls_event {
	__u64 ts_ns;   /* bpf_ktime_get_ns at capture */
	__u32 pid;     /* tgid — the process a human would name */
	__u32 tid;     /* thread that made the call */
	__s32 len;     /* bytes actually present in data[] */
	__s32 orig_len; /* bytes the call handled, before the TLS_CHUNK_MAX cap */
	__u8 dir;      /* enum BeeEye_tls_dir */
	__u8 _pad[3];
	__u8 comm[TLS_COMM_LEN];
	__u8 data[TLS_CHUNK_MAX];
};

#endif /* __BeeEye_TLS_EVENTS_H__ */
