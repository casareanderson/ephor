// SPDX-License-Identifier: GPL-2.0-only
/*
 * ephor-probe: the native eBPF probe for Ephor. Same three events as Ephor's bpftrace program, same output
 * lines, a few MB of memory instead of ~110 MB, and one static binary with nothing to install.
 *
 *   ephor-probe [LIBC_PATH ...]      attach, print one tab-separated line per event on stdout, run until killed
 *   ephor-probe -V                   print the version
 *
 * Output (what ephor/probe.py parses):
 *   E <pid> <ppid> <uid> <comm> <cgroup path> <argv, NUL-separated, \xNN-escaped>
 *   D <pid> <comm> <cgroup path> <name>
 *   C <pid> <comm> <cgroup path> <ip> <port>
 *
 * Read-only: it loads three observation hooks and never blocks, changes or injects anything.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "ephor-probe.h"
#include "ephor-probe.skel.h"

#define VERSION "0.3.0"
#define CG_ROOT "/sys/fs/cgroup"
#define CG_SLOTS 65536                  /* open-addressed cache of cgroup id -> path */

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

/* ------------------------------------------------------------------ cgroup id -> path */

struct cg { __u64 id; char *path; };
static struct cg cgs[CG_SLOTS];
static time_t last_scan;

static void cg_put(__u64 id, const char *path)
{
	unsigned i = (unsigned)(id * 0x9E3779B97F4A7C15ULL >> 48) & (CG_SLOTS - 1);
	for (unsigned n = 0; n < CG_SLOTS; n++, i = (i + 1) & (CG_SLOTS - 1)) {
		if (cgs[i].id == id)
			return;
		if (!cgs[i].id) {
			cgs[i].id = id;
			cgs[i].path = strdup(path);
			return;
		}
	}
}

static const char *cg_get(__u64 id)
{
	unsigned i = (unsigned)(id * 0x9E3779B97F4A7C15ULL >> 48) & (CG_SLOTS - 1);
	for (unsigned n = 0; n < CG_SLOTS && cgs[i].id; n++, i = (i + 1) & (CG_SLOTS - 1))
		if (cgs[i].id == id)
			return cgs[i].path;
	return NULL;
}

static int cg_visit(const char *p, const struct stat *st, int type, struct FTW *f)
{
	(void)f;
	if (type == FTW_D) {
		const char *rel = p + strlen(CG_ROOT);
		cg_put((__u64)st->st_ino, *rel ? rel : "/");
	}
	return 0;
}

static const char *cgroup_path(__u64 id)
{
	const char *p = cg_get(id);
	if (p)
		return p;
	time_t now = time(NULL);
	if (now != last_scan) {                 /* a new cgroup (a container just started): rescan, at most once a second */
		last_scan = now;
		nftw(CG_ROOT, cg_visit, 32, FTW_PHYS | FTW_MOUNT);
		p = cg_get(id);
	}
	return p ? p : "";
}

/* ------------------------------------------------------------------ output */

static void put_clean(const char *s, size_t n)
{
	for (size_t i = 0; i < n && s[i]; i++)
		putchar(s[i] == '\t' || s[i] == '\n' ? ' ' : s[i]);
}

static void put_escaped(const unsigned char *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		unsigned char c = b[i];
		if (c >= 0x20 && c < 0x7f && c != '\\')
			putchar(c);
		else
			printf("\\x%02x", c);
	}
}

static int on_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	const struct event *e = data;
	if (size < sizeof(*e) - ARG_MAX_BYTES)
		return 0;
	const char *cg = cgroup_path(e->cgroup);
	char comm[COMM_BYTES + 1] = {0};
	memcpy(comm, e->comm, COMM_BYTES);
	switch (e->kind) {
	case EV_EXEC:
		printf("E\t%u\t%u\t%u\t", e->pid, e->ppid, e->uid);
		put_clean(comm, COMM_BYTES);
		printf("\t%s\t", cg);
		put_escaped((const unsigned char *)e->data, e->len < ARG_MAX_BYTES ? e->len : ARG_MAX_BYTES);
		putchar('\n');
		break;
	case EV_DNS:
		printf("D\t%u\t", e->pid);
		put_clean(comm, COMM_BYTES);
		printf("\t%s\t", cg);
		put_clean(e->data, e->len < NAME_MAX_BYTES ? e->len : NAME_MAX_BYTES);
		putchar('\n');
		break;
	case EV_CONNECT: {
		char ip[INET6_ADDRSTRLEN] = "";
		inet_ntop(e->family == AF_INET ? AF_INET : AF_INET6, e->addr, ip, sizeof(ip));
		printf("C\t%u\t", e->pid);
		put_clean(comm, COMM_BYTES);
		printf("\t%s\t%s\t%u\n", cg, ip, e->port);
		break;
	}
	}
	fflush(stdout);
	return 0;
}

static int quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	return lvl == LIBBPF_WARN ? vfprintf(stderr, fmt, ap) : 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version"))) {
		printf("ephor-probe %s\n", VERSION);
		return 0;
	}
	libbpf_set_print(quiet);
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);          /* only matters on kernels before 5.11 */
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	struct ephor_probe_bpf *skel = ephor_probe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "ephor-probe: could not load the BPF program (root? BTF?): %s\n", strerror(errno));
		return 1;
	}
	struct bpf_link *l1 = bpf_program__attach(skel->progs.on_exec);
	struct bpf_link *l2 = bpf_program__attach(skel->progs.on_state);
	if (!l1 || !l2) {
		fprintf(stderr, "ephor-probe: could not attach the exec/connect tracepoints: %s\n", strerror(errno));
		return 1;
	}
	int hooked = 0;
	for (int i = 1; i < argc; i++) {
		LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "getaddrinfo");
		if (bpf_program__attach_uprobe_opts(skel->progs.on_getaddrinfo, -1, argv[i], 0, &uo))
			hooked++;
		else
			fprintf(stderr, "ephor-probe: no getaddrinfo hook on %s: %s\n", argv[i], strerror(errno));
	}
	nftw(CG_ROOT, cg_visit, 32, FTW_PHYS | FTW_MOUNT);
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ephor-probe: ring buffer: %s\n", strerror(errno));
		return 1;
	}
	fprintf(stderr, "ephor-probe %s: exec + connect attached, DNS hooks on %d libc file(s)\n", VERSION, hooked);
	while (!stop) {
		int err = ring_buffer__poll(rb, 500);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ephor-probe: poll: %s\n", strerror(-err));
			break;
		}
	}
	ring_buffer__free(rb);
	ephor_probe_bpf__destroy(skel);
	return 0;
}
