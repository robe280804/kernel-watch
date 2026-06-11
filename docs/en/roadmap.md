# Roadmap, limitations & known issues

## Roadmap (from the project README)

- [ ] Static profiler — pre-deploy image analysis with `syft`.
- [ ] Per-container behavioural baseline — ML autoencoder anomaly detection.
- [ ] REST API + WebSocket dashboard.
- [ ] TimescaleDB integration for event history.
- [ ] Kubernetes DaemonSet support.
- [ ] MITRE ATT&CK enrichment for all rules.

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
| Dashboard (WebSocket) | Not implemented | Roadmap only. |
| DB persistence | Not implemented | `Config.DSN()` ready; no connection, schema, or inserts. |
| Docker enrichment | Stub | `dockerInspect()` always returns "not implemented"; name = short ID, image = empty. |
| Ring-buffer sizing | No-op | `KW_EBPF_RINGBUF_SIZE` is loaded but not applied at eBPF load. |
| Tests | None | No `_test.go` files. |

## Remaining quirks worth fixing

- **"PPID" is the thread id** (`tracer.c` / `collector.go`): the low word of
  `bpf_get_current_pid_tgid()` is the kernel thread id, not the parent PID. Rename
  or fetch the real parent via `task_struct->real_parent` if you need true PPID.
- **Name-based filtering depends on enrichment**: `IsMonitored` matches container
  names, but until `dockerInspect` works the "name" is the 12-char short ID, so
  whitelist/blacklist by friendly name won't match.

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
