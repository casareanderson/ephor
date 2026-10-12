# ephor-probe

The native eBPF probe for `ephor watch --loop --ebpf`. It is optional: Ephor works without it, and falls back
to bpftrace when bpftrace is installed and this isn't.

| | ephor-probe | bpftrace fallback |
| --- | --- | --- |
| What you install | one ~2 MB static binary, no libraries | the bpftrace package |
| Memory while running | **~10 MB** | ~110 MB (bpftrace carries a compiler) |
| Events | the same three, the same output lines | the same three |

Measured on the reference box (Proxmox host, agents in an LXC), watching the same agent run `pip install`, a
lookup of `pypi-org.com` and a `curl`.

## What it does

Three read-only hooks, one ring buffer, one line per event on stdout:

- **process start** (`sched_process_exec`): pid, parent, uid, cgroup, and the command line copied from the new
  process's memory (first 512 bytes), so a command that exits a millisecond later is still seen in full
- **DNS lookup** (a uprobe on libc `getaddrinfo`): the name and the process asking. Ephor passes the libc of the
  host and of every running container on the command line
- **outgoing TCP connection** (`inet_sock_set_state` to SYN_SENT): destination address and port

It never blocks, changes or injects anything: the hooks are observation points (two tracepoints and a uprobe) and
the program uses no helper that writes to another process or alters a syscall.

## Requirements

Linux with BTF (`/sys/kernel/btf/vmlinux`, standard since about 5.8) and root. Works on x86_64 and arm64.
On a Raspberry Pi or other arm64 board, check that `/sys/kernel/btf/vmlinux` exists first: not every vendor
kernel is built with BTF. It is CO-RE: one binary runs on any such kernel.

## Get it

From a release: download `ephor-probe-x86_64` or `ephor-probe-aarch64`, check it against the `.sha256` file
next to it, then put it on PATH:

```bash
sha256sum -c ephor-probe-x86_64.sha256
install -m 755 ephor-probe-x86_64 /usr/local/bin/ephor-probe
ephor probe --check
```

Or build it. You need Docker and a BTF kernel; everything else happens in an Alpine container:

```bash
./probe/build.sh          # -> probe/ephor-probe, fully static (musl)
```

`make` works too on a box with clang, bpftool and static libbpf/libelf/zlib/libzstd. Debian's static libelf is
missing a piece, which is why `build.sh` links in Alpine.

## Where to run it

On the machine that owns the kernel. A VM, a Raspberry Pi or a bare-metal box: run it there. A Docker host: on
the host, or in a container started with `--privileged --pid=host` and `/sys/kernel/btf` mounted. Proxmox or
another LXC host with unprivileged containers: on the host, since the containers can't load eBPF. It sees every
container's processes and labels them by cgroup. macOS and Windows have no Linux eBPF; there Ephor's default
mode and `ephor dns-proxy` still work inside any Linux VM.

Licence: GPL-2.0-only (the kernel requires it for these helpers). Ephor itself stays AGPL-3.0.
