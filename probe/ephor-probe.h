/* SPDX-License-Identifier: GPL-2.0-only */
/* The one record the kernel side hands to user space. */
#ifndef EPHOR_PROBE_H
#define EPHOR_PROBE_H

#define ARG_MAX_BYTES  512      /* how much of a command line is copied (power of two: the verifier needs a bound) */
#define NAME_MAX_BYTES 256      /* a DNS name is at most 253 characters */
#define COMM_BYTES     16
#ifndef AF_INET
#define AF_INET  2
#define AF_INET6 10
#endif

enum { EV_EXEC = 1, EV_CONNECT = 2, EV_DNS = 3 };

struct event {
	__u32 kind;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u64 cgroup;                  /* cgroup v2 id = inode of the cgroup's directory under /sys/fs/cgroup */
	char  comm[COMM_BYTES];
	__u16 family;
	__u16 port;
	__u8  addr[16];
	__u32 len;
	char  data[ARG_MAX_BYTES];     /* NUL-separated argv for EV_EXEC, the name for EV_DNS */
};

#endif
