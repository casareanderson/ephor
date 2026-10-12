# ephor-probe: one static binary. Needs clang, bpftool, and static libbpf/libelf/zlib/libzstd (Debian/Ubuntu:
# apt install clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev libzstd-dev). The build host needs BTF
# (/sys/kernel/btf/vmlinux) to generate vmlinux.h; the binary then runs on any BTF kernel (CO-RE).
ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
OUT ?= ephor-probe

all: $(OUT)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ephor-probe.bpf.o: ephor-probe.bpf.c ephor-probe.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -Wno-missing-declarations -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

ephor-probe.skel.h: ephor-probe.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUT): ephor-probe.c ephor-probe.skel.h ephor-probe.h
	$(CC) -O2 -Wall -Wextra -I. $< -o $@ -static -lbpf -lelf -lz -lzstd
	strip $@

clean:
	rm -f vmlinux.h *.o *.skel.h $(OUT)

.PHONY: all clean
