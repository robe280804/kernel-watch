# Overview

## What is ContainerSentry?

ContainerSentry is a **Host Intrusion Detection System (HIDS)** specialised for
**Docker containers**. It observes the syscalls that container processes make and
raises alerts when it sees behaviour that healthy production containers should
never exhibit — for example launching a shell, reading `/etc/shadow`, accessing
the Docker socket, or running `nmap`.

The defining trait is **where** the observation happens: in the **Linux kernel**,
using **eBPF**. The application never injects anything into the monitored
containers. One daemon on the host sees everything.

## Why eBPF?

eBPF lets you run small, verified programs inside the kernel that are triggered by
kernel events (here, syscall entry points). Compared to the alternatives:

- **vs. an in-container agent:** nothing to install per container; an attacker who
  owns the container cannot tamper with the monitor (it runs in the kernel).
- **vs. a kernel module:** no recompilation, no risk of panicking the kernel; the
  eBPF verifier guarantees the program is safe to run.
- **vs. polling `/proc`:** events are pushed the instant a syscall fires, with no
  sampling gaps.

ContainerSentry uses **tracepoints** (stable kernel instrumentation points) on
four syscalls and streams events to user space through a **ring buffer**
(`BPF_MAP_TYPE_RINGBUF`), a high-throughput, lock-light kernel→userspace channel.

It is built with **CO-RE** (Compile Once – Run Everywhere) via BTF, so the same
compiled program runs across different kernel versions without recompiling against
each kernel's headers.

## Core concepts

| Term | Meaning in this project |
|---|---|
| **eBPF program** | The C code in `ebpf/tracer.c`, compiled to bytecode and loaded into the kernel. |
| **Tracepoint** | A stable kernel hook. We attach to `sys_enter_execve/openat/connect/clone`. |
| **Ring buffer** | The kernel→userspace channel carrying raw events (16 MB by default). |
| **Collector** | The Go code that loads the eBPF program, reads the ring buffer and parses events. |
| **Mapper** | Resolves a PID to its Docker container by parsing `/proc/<pid>/cgroup`. |
| **Detector** | A set of rules that inspect each enriched event and decide if it is an alert. |
| **Alerter** | Dispatches alerts to log file / webhook / Slack with rate limiting. |
| **CO-RE / BTF** | The mechanism that makes the eBPF program portable across kernels. |

## End-to-end picture

```
syscall in a container
        │  (kernel)
        ▼
ebpf/tracer.c  ──submit──►  ring buffer  ──►  collector (reads & parses)
                                                   │
                                                   ▼
                                         mapper: PID → container?
                                                   │ (skip host processes)
                                                   ▼
                                         detector: run 6 rules
                                                   │ (first match wins)
                                                   ▼
                                         alerter: severity filter +
                                         rate limit → log / webhook / Slack
```

Full detail in [architecture.md](architecture.md).

## Project maturity

The **core pipeline is complete and coherent**: kernel capture → parse → container
enrichment → rule detection → multi-destination alerting, all wired together in
`main.go` with graceful shutdown.

**What is solid today**

- eBPF collector with 4 syscall hooks and ring-buffer streaming.
- 6 MITRE-mapped detection rules.
- Multi-destination alerting (file, HMAC-signed webhook, Slack, stdout).
- Per-container sliding-window rate limiting.
- Container resolution via cgroups (v1 and v2) with a TTL cache.
- Multi-stage Dockerfile and a production-shaped `docker-compose.yml`.

**What is incomplete or stubbed** (see [roadmap.md](roadmap.md) for the full list)

- REST API / dashboard: a port is configured (`CS_API_PORT`) but there are **no
  HTTP handlers** yet.
- Database persistence: TimescaleDB is defined in Compose, but there is **no schema
  and no insert logic**, and the `./migrations` directory does not exist yet.
- `dockerInspect()` in the mapper is a **stub** — container name/image are not
  enriched from the Docker API; the short container ID is used as the name.
- The configured eBPF ring-buffer size is **not actually applied** at load time.
- No tests, no `go.sum` committed, not a git repository.
- A few code quirks documented in [components.md](components.md) and
  [roadmap.md](roadmap.md).
