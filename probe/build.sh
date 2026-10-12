#!/bin/sh
# Build ephor-probe as one fully static binary for this machine's architecture.
# Needs only Docker and a kernel with BTF (/sys/kernel/btf/vmlinux): everything else happens in an Alpine container.
#   ./build.sh            -> ./ephor-probe
set -e
cd "$(dirname "$0")"
docker run --rm -v "$PWD":/src -v /sys/kernel/btf:/sys/kernel/btf:ro -w /src alpine:3.20 sh -ec '
  apk add -q --no-progress make clang llvm bpftool gcc musl-dev libbpf-dev elfutils-dev zlib-static zstd-static \
      linux-headers >/dev/null
  make clean >/dev/null
  make CC=gcc
'
ls -la ephor-probe
sha256sum ephor-probe
