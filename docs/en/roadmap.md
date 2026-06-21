# Roadmap, limitations & known issues

## Roadmap (from the project README)

- [x] Context-aware detection — process-lineage + argv + Docker enrichment
  (Phase 1, see [detection-rules.md](detection-rules.md)).
- [x] MITRE ATT&CK enrichment for all rules.
- [x] Detection coverage beyond Execution — Persistence (cron/systemd/ld.so.preload
  writes), process injection (`ptrace`), kernel-module & eBPF-program loads.
- [ ] Remaining coverage — IPv6 `connect`, a connect-based C2 rule, and
  attack-chain correlation (single alerts → incidents).
- [x] TimescaleDB persistence of alerts — queryable history + retention
  (`internal/storage`, `KW_DB_ENABLED`).
- [ ] Behavioural-anomaly engine — STIDE / n-gram syscall-sequence baseline per
  workload (Phase 2; learning mode + persisted profiles).
- [ ] Static profiler — pre-deploy image analysis with `syft`.
- [ ] REST API + WebSocket dashboard (query the stored alerts).
- [ ] Kubernetes DaemonSet support.
- [ ] Runtime enforcement (kill offending process, Tetragon-style).

## Stabilization fixes already applied

These were blocking a working build/run and have been fixed in-repo:

- **bpf2go target package**: the `//go:generate` directive moved from `main.go` to
  `internal/collector/gen.go`, so the generated `tracerObjects`/`loadTracerObjects`
  land in the `collector` package (where they're used). Previously they'd have been
  generated into `package main` and `collector` would not compile.
- **Reproducible eBPF build**: `tracer.c` is self-contained — it declares the one
  kernel struct it needs (stable tracepoint ABI), so there is **no `vmlinux.h` and no
  host BTF** dependency. The Dockerfile installs `libbpf-dev` + `linux-libc-dev` and
  drops the Debian-incompatible `linux-headers-generic`. Result: `git clone` +
  `docker compose up --build` works on any Linux host.
- **`go.sum` auto-generated**: the Dockerfile copies it optionally (`go.sum*`) and
  `go mod download` generates it in-build — no manual `go mod tidy` step.
- **eBPF actually loads**: the container runs as **root** with `cap_drop: ALL` +
  scoped `cap_add`. A non-root user would not retain the effective capabilities
  `cap_add` grants, so eBPF loading would have silently failed.
- **PID resolution**: `docker-compose.yml` sets `pid: "host"`, so eBPF host PIDs
  resolve via `/proc/<pid>/cgroup`. Without it the detector saw every event as a
  host process and fired **zero** alerts. (Unused BTF/bpffs/`/proc` mounts removed.)
- **execve detection**: rules now match the basename of the executed binary
  (`e.Filename`) instead of `comm`, which at `sys_enter_execve` still holds the
  caller's name — so shell/tool/pkg-manager rules now actually fire.
- **Cleanup**: removed the `strings` shim in `alerter.go` (real `import "strings"`),
  renamed the startup log to "KernelWatch starting", added `migrations/.gitkeep`,
  removed a stray brace-expansion directory.

## Still incomplete / stubbed

| Area | State | Detail |
|---|---|---|
| REST API | Not implemented | `KW_API_PORT`/`KW_API_TOKEN` exist; no HTTP server or handlers. |
| Dashboard | Done (read + suppressions) | Next.js UI in `dashboard/` over the REST API; optional `dashboard` compose service. Live WebSocket stream still pending. |
| DB persistence | Done (alerts) | `internal/storage` writes alerts to a TimescaleDB hypertable (async, resilient) with retention. Raw-event storage still out of scope. |
| Docker enrichment | Done | `internal/container/docker.go` resolves real name/image via the Docker socket; falls back to short ID if unreachable. |
| Ring-buffer sizing | No-op | `KW_EBPF_RINGBUF_SIZE` is loaded but not applied at eBPF load. |
| Tests | Present | Table-driven rule tests in `internal/detector/detector_test.go`; CI runs `go vet` + `go test` (`.github/workflows/ci.yml`). |
| Behavioural baseline | Planned | Signature engine done; STIDE anomaly engine is Phase 2. |

## Remaining quirks worth fixing

- **(Fixed) "PPID" was the thread id**: the eBPF field is now named `tid`
  (`tracer.c` / `collector.go`) to reflect that the low word of
  `bpf_get_current_pid_tgid()` is the thread id. True process lineage is resolved
  in userspace via `/proc/<pid>/stat` (see `internal/container/parent.go`).
- **(Fixed) Name-based filtering**: with Docker enrichment in place, `IsMonitored`
  and `KW_CONTAINER_*` now match real container names, not short IDs.

## A realistic forward view

The hard, differentiating part — kernel-level eBPF capture with a clean
collector→detector→alerter pipeline — is **done and coherent**. What remains is
mostly the "unglamorous but necessary" plumbing:

**Near term (finish the MVP)**
1. (Done) Reproducible build + working eBPF load — see "Stabilization fixes" above.
2. Implement Docker-API enrichment (`dockerInspect` / wire `ParseDockerList`) so
   alerts carry real container names and images and name-based filtering works.
3. REST API + persistence (TimescaleDB schema, inserts, authenticated query
   endpoints using `KW_API_TOKEN`).

**Medium term (robustness)**
4. Unit tests for the pure logic (rules, `extractContainerID`, rate limiter) and
   the small code-quirk fixes above; add CI.
5. A web dashboard over the API (live feed + history).
6. Behavioural baselining per container to complement the static rules.

**Long term (scale)**
7. Kubernetes DaemonSet — the jump from single-host Docker to cluster-wide coverage.
8. Deeper MITRE enrichment and event correlation (single alerts → attack chains).

If the project clears the near-term plumbing, it has a credible path to becoming a
lightweight, open alternative in the space occupied by tools like Falco/Sysdig and
Aqua — the architecture and security posture (kernel-space, least-privilege,
non-root, MITRE-tagged) are already sound.
