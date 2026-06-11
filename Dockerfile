# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

# Install clang/LLVM and headers for eBPF compilation.
# - libbpf-dev   : <bpf/bpf_helpers.h> and the helper declarations
# - linux-libc-dev: stable UAPI <linux/bpf.h> / <linux/types.h>
# tracer.c is self-contained (it declares the one kernel struct it needs), so we
# need NO host BTF, NO vmlinux.h, and NO kernel-headers package at build time.
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

# bpf2go compiles with `-target bpf`, which drops clang's multiarch include path.
# On Debian the UAPI <asm/types.h> lives under /usr/include/x86_64-linux-gnu/asm,
# so without this symlink the compile fails with "'asm/types.h' file not found".
# (amd64 is assumed — consistent with GOARCH=amd64 in the build step below.)
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm

WORKDIR /build

# Allow the toolchain to add missing go.mod/go.sum entries on the fly.
# `go generate` runs `go run .../cmd/bpf2go`, whose transitive dependencies are
# NOT covered by `go mod download github.com/cilium/ebpf`; without a committed
# go.sum this would fail with "missing go.sum entry". -mod=mod lets go fetch and
# record them in-build, so a fresh clone needs no manual `go mod tidy`.
ENV GOFLAGS=-mod=mod

# Download dependencies first (better layer caching).
# go.sum is optional: the glob tolerates its absence and `go mod download`
# generates it in-build, so a fresh clone needs no manual `go mod tidy`.
# (Committing go.sum is still recommended for supply-chain pinning.)
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Generate eBPF bytecode (compiles ebpf/tracer.c → internal/collector/tracer_bpf*.go).
# tracer.c is self-contained, so no vmlinux.h / host BTF is required here.
RUN go generate ./...

# Build the Go binary (static, no CGO for the Go parts)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /kernelwatch .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime deps: libelf for eBPF loading
RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create log directory
RUN mkdir -p /var/log/kernelwatch

# Copy binary
COPY --from=builder /kernelwatch /usr/local/bin/kernelwatch

# ── Privileges ────────────────────────────────────────────────────────────────
# KernelWatch must load eBPF programs and attach tracepoints, which require
# *effective* CAP_SYS_ADMIN (plus SYS_PTRACE / NET_ADMIN). A non-root USER in a
# container does NOT retain effective capabilities granted via `cap_add` (that
# would need ambient-capability plumbing), so eBPF loading would silently fail.
#
# We therefore run as root and let docker-compose.yml drop ALL capabilities and
# add back only the three we need — i.e. root with a tightly scoped capability
# set, NOT a fully privileged container:
#   - SYS_ADMIN  : load eBPF programs / attach tracepoints
#   - SYS_PTRACE : read /proc/<pid>/cgroup for container mapping
#   - NET_ADMIN  : network tracepoints

ENTRYPOINT ["/usr/local/bin/kernelwatch"]
