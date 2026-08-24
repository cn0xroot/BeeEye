// 蜂眼 BeeEye — TLS plaintext capture via uprobes (F14, see TLS-DECRYPT.md).
//
// This attaches to a userspace TLS library and reads the plaintext buffer on
// either side of the encryption boundary:
//
//   SSL_write(SSL *, const void *buf, int num)  — buf holds plaintext already
//   SSL_read (SSL *, void *buf, int num)        — buf holds plaintext only
//                                                 once the call has returned
//
// Why this program needs no per-OpenSSL-version build, unlike eCapture's
// several dozen: it only ever touches *function arguments*, which the ABI
// fixes, and never reaches inside the SSL struct. The master-key extraction
// eCapture also does must read ssl->s3->client_random, whose offset moves
// every release — that is what forces a build per version. Staying on this
// side of that line is a deliberate scope choice (TLS-DECRYPT.md §1).
//
// SCOPE, because it is easy to misread: a uprobe reaches only libraries
// running on THIS kernel. It captures the gateway's own processes and can
// never touch a camera, a lock or a phone. It is the content-level companion
// to internal/procmap, which attributes exactly the same set of flows.
//
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#include "BeeEye_tls_events.h"

/* ---------------------------------------------------------------- maps */

/* Plaintext channel to userspace. Sized smaller than the packet program's
 * ring: these records are large and a backlog of application content is not
 * something to hold on to. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 << 20); /* 2 MiB */
} tls_events SEC(".maps");

/* SSL_read hands back its plaintext through a caller-supplied buffer, so the
 * pointer has to survive from the call to its return. Keyed by pid_tgid: two
 * threads of one process can be inside SSL_read at the same time, and keying
 * by pid alone would let one thread's return read the other's buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} active_reads SEC(".maps");

/* Master-key extraction (see BeeEye_ssl_offsets in BeeEye_tls_events.h).
 * Populated by userspace (Peeker.SetMasterKeyOffsets) once it knows a given
 * pid is running an OpenSSL version this build has real, source-verified
 * offsets for — a pid absent from this map just never attempts extraction,
 * same as before this existed. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);  /* pid (tgid) */
	__type(value, struct BeeEye_ssl_offsets);
} ssl_offsets SEC(".maps");

/* Dedupes keylog records per TLS session so a chatty long-lived connection
 * reports its master secret once, not on every SSL_write. Keyed by the raw
 * SSL_SESSION* pointer, which is stable for the life of the session. LRU so a
 * gateway that runs for weeks cannot grow this without bound. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);  /* SSL_SESSION* */
	__type(value, __u8);
} keylog_seen SEC(".maps");

/* The event struct reaches userspace only through bpf_ringbuf_reserve's void *,
 * and sizeof() gets constant-folded, so nothing would otherwise reference the
 * type and the compiler would emit no BTF for it. This declaration forces it
 * out, which is what lets TestTLSEventLayoutMatchesBTF check the Go decoder's
 * offsets against the real layout instead of against a comment. */
struct BeeEye_tls_event *__BeeEye_tls_event_btf __attribute__((unused));

/* ---------------------------------------------------------------- helpers */

/* submit copies at most TLS_CHUNK_MAX bytes of user memory into a ringbuf
 * record. A short or failed read drops the record rather than shipping a
 * partially-filled buffer that would read as real content. */
static __always_inline int submit(void *buf, __s64 orig_len, __u8 dir)
{
	if (orig_len <= 0)
		return 0;

	/* Bounding the copy for the verifier. The compare alone is not enough —
	 * it rejects that with "R2 unbounded memory access" — because the value
	 * is widened to 32 bits before the helper call. The mask is what makes
	 * the bound a property of the value itself. */
	__u32 len = (__u32)orig_len;
	if (len > TLS_CHUNK_CAP)
		len = TLS_CHUNK_CAP;
	len &= TLS_CHUNK_CAP;

	struct BeeEye_tls_event *ev =
		bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
	if (!ev)
		return 0; /* ring full: drop this chunk, never block the app */

	__u64 id = bpf_get_current_pid_tgid();
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = (__u32)(id >> 32);
	ev->tid = (__u32)id;
	ev->orig_len = (__s32)orig_len;
	ev->dir = dir;
	ev->_pad[0] = 0;
	ev->_pad[1] = 0;
	ev->_pad[2] = 0;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	if (bpf_probe_read_user(&ev->data, len, buf) != 0) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}
	ev->len = (__s32)len;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* try_extract_master_secret reads the TLS 1.2 master secret out of ssl (an
 * `SSL *` argument) using this process's offset table, and submits one
 * TLS_DIR_KEYLOG record the first time a given session is seen with a
 * populated (48-byte) master key. A no-op for any pid with no entry in
 * ssl_offsets, for a still-mid-handshake call (master_key_length reads 0),
 * and for anything that is not exactly the fixed TLS 1.2 master-secret
 * length — see BeeEye_ssl_offsets's doc comment for why TLS 1.3 is
 * deliberately excluded rather than guessed at. */
static __always_inline void try_extract_master_secret(void *ssl)
{
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct BeeEye_ssl_offsets *off = bpf_map_lookup_elem(&ssl_offsets, &pid);
	if (!off)
		return;

	__u64 session = 0;
	if (bpf_probe_read_user(&session, sizeof(session), ssl + off->session_off) != 0)
		return;
	if (!session)
		return;

	if (bpf_map_lookup_elem(&keylog_seen, &session))
		return; /* already reported for this session */

	__u64 master_key_len = 0;
	if (bpf_probe_read_user(&master_key_len, sizeof(master_key_len),
				 (void *)session + off->master_key_len_off) != 0)
		return;
	/* SSL3_MASTER_SECRET_SIZE: the one fixed length this build knows how
	 * to interpret. A TLS 1.3 session's master_key field holds a
	 * different-length resumption PSK, and a not-yet-established session
	 * reads 0 here — both correctly skipped by this check rather than
	 * shipping a wrong-length or all-zero "secret". */
	if (master_key_len != 48)
		return;

	struct BeeEye_tls_event *ev =
		bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
	if (!ev)
		return;

	__u64 id = bpf_get_current_pid_tgid();
	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid;
	ev->tid = (__u32)id;
	ev->dir = TLS_DIR_KEYLOG;
	ev->_pad[0] = 0;
	ev->_pad[1] = 0;
	ev->_pad[2] = 0;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	__builtin_memset(&ev->data, 0, 88);

	if (bpf_probe_read_user(&ev->data[0], 32, ssl + off->client_random_off) != 0 ||
	    bpf_probe_read_user(&ev->data[40], 48, (void *)session + off->master_key_off) != 0) {
		bpf_ringbuf_discard(ev, 0);
		return;
	}
	__u64 mklen_le = master_key_len; /* BPF target is little-endian */
	__builtin_memcpy(&ev->data[32], &mklen_le, 8);

	ev->len = 88;
	ev->orig_len = 88;
	bpf_ringbuf_submit(ev, 0);

	__u8 one = 1;
	bpf_map_update_elem(&keylog_seen, &session, &one, BPF_ANY);
}

/* ---------------------------------------------------------------- probes */

/* SSL_write: the buffer is plaintext at entry, so there is nothing to wait
 * for. Using the argument rather than the return value means a partial write
 * is reported as what the application asked to send, which is what an
 * operator reading this pane is trying to see. */
SEC("uprobe/SSL_write")
int BeeEye_uprobe_ssl_write(struct pt_regs *ctx)
{
	void *ssl = (void *)PT_REGS_PARM1(ctx);
	void *buf = (void *)PT_REGS_PARM2(ctx);
	__s64 num = (__s64)(int)PT_REGS_PARM3(ctx);
	/* By the time application data is written the handshake is complete
	 * and the master secret is populated, so this is a convenient, cheap
	 * (map-lookup-and-return for the common case of no offsets known)
	 * place to also try a keylog extraction — see BeeEye_ssl_offsets. */
	try_extract_master_secret(ssl);
	return submit(buf, num, TLS_DIR_WRITE);
}

/* SSL_read: at entry the buffer is uninitialised — reading it here would ship
 * whatever the application last left on its heap. Stash the pointer and wait. */
SEC("uprobe/SSL_read")
int BeeEye_uprobe_ssl_read(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 buf = (__u64)PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&active_reads, &id, &buf, BPF_ANY);
	return 0;
}

/* SSL_read return: the return value is the byte count actually decrypted. A
 * zero or negative return means no plaintext (EOF, want-read, error), so the
 * stashed pointer is dropped without a record. */
SEC("uretprobe/SSL_read")
int BeeEye_uretprobe_ssl_read(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 *buf = bpf_map_lookup_elem(&active_reads, &id);
	if (!buf)
		return 0;
	__u64 addr = *buf;
	bpf_map_delete_elem(&active_reads, &id);

	/* A uretprobe's pt_regs no longer holds the original arguments, only
	 * the return value — but SSL_read's first argument (the SSL*) is
	 * exactly what active_reads was keyed toward stashing for buf, so
	 * ssl3.tmp isn't available here without stashing it too. Extraction
	 * on the write side already covers every request/response pair that
	 * ever sends application data, which is effectively all of them; a
	 * read-only, request-less connection (unusual for HTTP-shaped
	 * traffic) simply relies on that side never having fired, same as
	 * plaintext capture already does not invent a write that never
	 * happened. */
	__s64 ret = (__s64)(int)PT_REGS_RC(ctx);
	return submit((void *)addr, ret, TLS_DIR_READ);
}
