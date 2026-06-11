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
# On Debian the UAPI <asm/types.h> lives under /usr/include/<arch>-linux-gnu/asm,
# so without this symlink the compile fails with "'asm/types.h' file not found".
# uname -m makes this work on amd64 (x86_64) and arm64 (aarch64) native builds.
RUN ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

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

# Build the Go binary (static, no CGO for the Go parts). VERSION is stamped into
# the binary (printed by `kernelwatch -version` and logged at startup). GOARCH is
# left to the builder's native arch so arm64 hosts produce arm64 binaries.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w -X main.version=${VERSION}" -o /kernelwatch .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime deps:
#  - libelf1        : eBPF object loading
#  - ca-certificates: outbound TLS (webhook/Slack alerts)
#  - procps         : provides `pgrep`, used by the compose healthcheck. Without
#                     it the healthcheck errors "not found" → container is marked
#                     unhealthy → an autoheal sidecar (if present) restarts it in
#                     a loop despite the daemon being perfectly healthy.
RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    procps \
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
