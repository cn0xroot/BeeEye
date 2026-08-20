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

/* ---------------------------------------------------------------- probes */

/* SSL_write: the buffer is plaintext at entry, so there is nothing to wait
 * for. Using the argument rather than the return value means a partial write
 * is reported as what the application asked to send, which is what an
 * operator reading this pane is trying to see. */
SEC("uprobe/SSL_write")
int BeeEye_uprobe_ssl_write(struct pt_regs *ctx)
{
	void *buf = (void *)PT_REGS_PARM2(ctx);
	__s64 num = (__s64)(int)PT_REGS_PARM3(ctx);
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

	__s64 ret = (__s64)(int)PT_REGS_RC(ctx);
	return submit((void *)addr, ret, TLS_DIR_READ);
}
