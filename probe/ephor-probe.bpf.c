// SPDX-License-Identifier: GPL-2.0-only
// ephor-probe, kernel side. Three read-only hooks; every event goes to user space through one ring buffer.
// Nothing here blocks, changes or writes to anything outside the ring buffer.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ephor-probe.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);           /* 4 MB: room for bursts (a `make -j` starts hundreds of processes) */
} events SEC(".maps");

static __always_inline void fill_common(struct event *e)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->cgroup = bpf_get_current_cgroup_id();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* A process started: copy its command line straight from the new process's memory, so even one that exits a
 * millisecond later is seen in full. */
SEC("tp/sched/sched_process_exec")
int on_exec(void *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e);
	e->kind = EV_EXEC;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	unsigned long start = BPF_CORE_READ(t, mm, arg_start);
	unsigned long end = BPF_CORE_READ(t, mm, arg_end);
	unsigned long n = end - start;
	if (n > ARG_MAX_BYTES)
		n = ARG_MAX_BYTES;
	n &= (ARG_MAX_BYTES * 2 - 1);           /* a bound the verifier can see; n is already <= ARG_MAX_BYTES */
	e->len = 0;
	if (n > 0 && n <= ARG_MAX_BYTES && bpf_probe_read_user(e->data, n, (void *)start) == 0)
		e->len = n;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* An outgoing TCP connection: the moment the SYN is sent, so a sub-second connection is still seen. */
SEC("tp/sock/inet_sock_set_state")
int on_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->newstate != TCP_SYN_SENT || ctx->protocol != IPPROTO_TCP)
		return 0;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e);
	e->kind = EV_CONNECT;
	e->family = ctx->family;
	e->port = ctx->dport;
	if (ctx->family == AF_INET)
		bpf_probe_read_kernel(e->addr, 4, ctx->daddr);
	else
		bpf_probe_read_kernel(e->addr, 16, ctx->daddr_v6);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* A DNS lookup through libc: user space attaches this to getaddrinfo in each libc it was given. */
SEC("uprobe")
int BPF_UPROBE(on_getaddrinfo, const char *node)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e);
	e->kind = EV_DNS;
	long n = bpf_probe_read_user_str(e->data, NAME_MAX_BYTES, node);
	e->len = n > 0 ? n - 1 : 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
