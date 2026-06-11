# Deployment

## Requirements

- **Linux kernel 5.15+** (6.x recommended) — needs ring-buffer + BTF-defined map
  support (standard on modern kernels).
- **Docker + Docker Compose**.
- For source builds: `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`.

> Fully reproducible: a `git clone` + `docker compose up -d --build` is enough on
> **any** Linux host. The eBPF program is self-contained (no host BTF / `vmlinux.h`),
> and `go.sum` is generated in-build — no `bpftool`, no manual `go mod tidy`.

> KernelWatch monitors the Linux kernel, so it must run on a Linux host. On
> Windows/macOS it only runs inside a Linux VM (e.g. Docker Desktop's VM), where it
> sees that VM's kernel — fine for testing, not a real host deployment.

## Quick start (Docker Compose)

```bash
cp .env.example .env
# At minimum set KW_SERVER_NAME and a strong KW_API_TOKEN; configure alert
# destinations (webhook/Slack) if you want them.

docker compose up -d --build
docker compose logs -f kernelwatch
```

## What Compose sets up

**`kernelwatch` service**

- `network_mode: host` — see all container network activity.
- `pid: "host"` — share the host PID namespace so eBPF host PIDs resolve via
  `/proc/<pid>/cgroup` (without this, container resolution fails and no alerts fire).
- `cap_drop: ALL` + `cap_add: SYS_ADMIN, SYS_PTRACE, NET_ADMIN` with
  `privileged: false` — root with a tightly scoped capability set (eBPF needs
  effective caps, which a non-root user wouldn't retain).
- `security_opt: apparmor:unconfined` — required for eBPF on some distros (Ubuntu).
- Mounts (kept minimal for portability):
  - `/var/run/docker.sock:ro` — container metadata (for future enrichment).
  - `kernelwatch-logs` volume — persists `alerts.json`.
  - No BTF / bpffs / `/proc` bind mounts are needed (no CO-RE; `/proc` comes via
    `pid:host`).
- `healthcheck`: `pgrep kernelwatch`.
- `restart: unless-stopped`.

**`db` service (TimescaleDB)**

- `timescale/timescaledb:latest-pg16`.
- Credentials from `KW_DB_*`.
- `./migrations:/docker-entrypoint-initdb.d:ro` — SQL here runs on **first** start
  (`0001_alerts.sql` creates the alerts hypertable). The app also applies the same
  schema idempotently at startup, so existing volumes are covered too.
- Bound to `127.0.0.1:5432` only — never expose Postgres to the internet.

> The daemon persists **alerts** to this database when `KW_DB_ENABLED=true`
> (Compose sets it). The store is best-effort — if the DB is down KernelWatch keeps
> monitoring and the log file remains the durable fallback. Raw syscall events are
> not stored. Query history with
> `docker compose exec db psql -U kernelwatch -c "select timestamp,severity,rule_id,container_name,reason from alerts order by timestamp desc limit 20;"`.

## The Docker image (multi-stage)

**Stage 1 — builder** (`golang:1.22-bookworm`)
1. Installs `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`.
2. `COPY go.mod go.sum* ./` + `go mod download` for layer caching. `go.sum` is
   optional — it's generated in-build if absent, so a fresh checkout needs no
   manual `go mod tidy` (committing it is still recommended for pinning).
3. `go generate ./...` compiles `ebpf/tracer.c` → `internal/collector/tracer_bpf*.go`.
   `tracer.c` is self-contained (manual kernel struct), so no `vmlinux.h` and no
   host BTF are needed at build time.
4. Builds a stripped static binary: `CGO_ENABLED=0 ... -ldflags="-s -w"`.

**Stage 2 — runtime** (`debian:bookworm-slim`)
1. Installs `libelf1`, `ca-certificates`.
2. Creates `/var/log/kernelwatch`.
3. Copies the binary. Runs as root (required for eBPF); privileges are constrained
   to a scoped capability set by `docker-compose.yml`.

## Deploying to additional hosts

The design goal is **one image, per-host `.env`**:

```bash
git clone <repo> && cd kernelwatch
cp .env.example .env
# edit KW_SERVER_NAME, KW_API_TOKEN, alert destinations
docker compose up -d --build
```

## Build & run without Docker

```bash
sudo apt install -y clang llvm libbpf-dev linux-libc-dev
go generate ./...    # compile eBPF → internal/collector/tracer_bpf*.go
go build -o kernelwatch .
sudo ./kernelwatch   # root required to load eBPF
```

> `go generate` runs the directive in `internal/collector/gen.go`, so the generated
> scaffolding lands in the `collector` package. No `vmlinux.h` / `bpftool` and no
> pre-existing `go.sum` are required.

Configuration is read from the process environment (export `KW_*` vars or source a
`.env`).

## Operational notes

- **Capabilities vs. privileged:** some kernels/distros may still require additional
  relaxations; if eBPF load fails, check kernel lockdown and AppArmor.
- **Healthcheck:** the container healthcheck runs `kernelwatch -health`, which
  passes only when the daemon's heartbeat file is fresh (event loop alive and
  draining) — stronger than a process-exists check. A wedged or dead daemon is
  marked unhealthy and restarted.
- **Event-loss visibility:** the periodic `stats` log line reports `kernel_drops`
  (ring-buffer overflow), `channel_drops` (userspace backpressure), and
  `enrich_miss_*` (process exited before `/proc` lineage/argv could be read). If
  `kernel_drops` climbs, raise `KW_EBPF_RINGBUF_SIZE`.
- **Log growth:** `alerts.json` rotates automatically at `KW_LOG_MAX_MB` keeping
  `KW_LOG_MAX_BACKUPS` files, so it cannot fill the host disk.
- **Resource limits:** Compose caps the daemon at `cpus: 1.0`, `mem_limit: 256m`,
  `pids_limit: 512` so it can never starve the host's real workload — raise on
  very high-syscall-volume hosts.
- **Alert delivery:** webhook/Slack delivery retries with backoff; every alert
  carries a stable `id` so a delivered alert can be correlated to its DB row.
- **Pinned image:** for fleet deployments, pull a released tag
  (`ghcr.io/<owner>/kernelwatch:<version>`, built by the Release workflow) instead
  of `build:` so every host runs an identical, prebuilt binary.
- **Verifying it works:** after `up`, exec a shell into any *other* container
  (`docker exec -it <c> sh`) and watch a `shell execution inside container` alert
  appear in `docker compose logs -f kernelwatch`.
