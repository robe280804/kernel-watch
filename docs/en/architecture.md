# Architecture

## Components

ContainerSentry is a single Go binary built from five internal packages plus the
eBPF program. Each package has one clear responsibility.

```
main.go ──────────── wires everything, owns the event loop
│
├── internal/config     (config.go)     env vars → validated Config
├── internal/container  (mapper.go)      PID → container Info (cgroup parsing + cache)
├── internal/collector  (collector.go)   load eBPF, read ring buffer, parse + enrich
├── internal/detector   (detector.go)    run rules against events → Alert
└── internal/alerter    (alerter.go)     dispatch alerts (log/webhook/Slack) + rate limit

ebpf/tracer.c ──────── kernel-space syscall hooks → ring buffer
```

### Dependency direction

```
config  ◄──── everyone reads config
container (mapper)  ◄──── collector uses it to enrich events
collector  ──── produces collector.Event, imports container + config
detector  ──── imports collector (Event) and alerter (Alert)
alerter  ──── imports config; defines the Alert type
main  ──── imports all of the above
```

`alerter.Alert` is the shared output type: the detector builds it, the alerter
sends it. `collector.Event` is the shared input type the detector consumes.

## End-to-end data flow

1. **Kernel capture** — A container process makes a syscall. The matching
   tracepoint in `tracer.c` fires, reserves a slot in the ring buffer, fills a
   `struct event` (PID, PPID, UID, type, `comm`, filename, dst port/IP, timestamp)
   and submits it.

2. **Read & parse** — `collector.readLoop()` blocks on `reader.Read()`. Each record
   is binary-decoded (little-endian) into a `RawEvent`, then converted to an
   enriched `Event` (`parseEvent`): null-terminated C strings → Go strings, the
   raw IPv4 `uint32` → `net.IP`, nanosecond timestamp → `time.Time`.

3. **Container enrichment** — `mapper.Resolve(pid)` returns the container `Info` or
   `nil` for host processes. Result is cached per PID (`nil` is cached too).

4. **Filtering** — Two early-outs in `readLoop`:
   - If the event belongs to a container that is **not monitored**
     (`config.IsMonitored` → blacklist/whitelist), it is dropped.
   - If it is an `open` on a **noisy path** (`/proc/`, `/sys/`, `/dev/null`,
     `/dev/urandom`, `/etc/localtime`, `/usr/share/zoneinfo`), it is dropped.
   Surviving events are sent on a **buffered channel (capacity 1000)**. If the
   channel is full the event is dropped with a warning (back-pressure protection).

5. **Detection** — `main` reads the channel and calls `detector.Check(event)`.
   The detector **ignores host events** (`event.Container == nil`) and otherwise
   runs the rules **in order**; the **first** rule that matches wins. The detector
   then stamps the alert with container ID/name, image, PID, process name, syscall
   name and timestamp.

6. **Alerting** — `alerter.Send(alert)`:
   - Drops the alert if its severity is below `CS_ALERT_MIN_SEVERITY`.
   - Applies **per-container sliding-window rate limiting**
     (`CS_ALERT_MAX_RATE` events per `CS_ALERT_RATE_WINDOW` seconds).
   - Stamps `ServerName` and (if missing) `Timestamp`.
   - Dispatches to every enabled destination: JSON log file (synchronous) and
     webhook + Slack (each in its own goroutine).

7. **Stats & shutdown** — `main` counts `processed`/`alerted`, logging stats every
   10 000 events. On SIGINT/SIGTERM it stops the collector, closes the alerter,
   and logs the final counts.

## The binary event contract

The single most important invariant in the codebase: the C `struct event` in
`tracer.c` and the Go `RawEvent` in `collector.go` **must have identical memory
layout**. The decode is a raw `binary.Read` with `binary.LittleEndian`, so field
order, sizes and padding all matter.

| C field (`tracer.c`) | Go field (`RawEvent`) | Size | Notes |
|---|---|---|---|
| `__u32 pid` | `PID uint32` | 4 | high 32 bits of `pid_tgid` |
| `__u32 ppid` | `PPID uint32` | 4 | low 32 bits of `pid_tgid` (see note) |
| `__u32 uid` | `UID uint32` | 4 | |
| `__u8 event_type` | `EventType uint8` | 1 | `EVENT_*` constant |
| _(padding)_ | `_ [3]byte` | 3 | align next field |
| `char comm[16]` | `Comm [16]byte` | 16 | process name |
| `char filename[128]` | `Filename [128]byte` | 128 | execve/open path |
| `__u16 dport` | `DPort uint16` | 2 | network byte order |
| _(padding)_ | `_ [2]byte` | 2 | align next field |
| `__u32 daddr` | `DAddr uint32` | 4 | IPv4, little-endian on x86 |
| `__u64 timestamp_ns` | `TimestampNS uint64` | 8 | `bpf_ktime_get_ns()` |

> **Note on PID/PPID:** the kernel's `bpf_get_current_pid_tgid()` returns
> `tgid<<32 | pid`. The code maps the high word to `PID` and the low word to
> `PPID`. The low word is actually the kernel *thread id*, not the parent PID, so
> "PPID" is a slight misnomer in the current implementation.

The event-type constants are duplicated in two places and must stay in sync:
`EVENT_EXECVE/OPEN/CONNECT/CLONE` (1–4) in `tracer.c` and `EventExecve/Open/
Connect/Clone` in `collector.go`.

## Concurrency model

- **One reader goroutine** (`readLoop`) feeds the buffered event channel.
- **The main goroutine** consumes the channel and runs detection synchronously.
- **Webhook and Slack sends** run in their own short-lived goroutines so a slow
  endpoint never blocks the event loop.
- **The mapper** has an internal **eviction goroutine** (`evictLoop`, ticks every
  30 s) clearing cache entries older than the TTL (5 minutes, set in `main.go`).
  The cache is guarded by an `sync.RWMutex`; rate-limit state by its own mutex.

## Runtime environment

The daemon needs host visibility, granted in `docker-compose.yml`:

- `network_mode: host` — to observe all container network activity.
- `pid: "host"` — so eBPF host PIDs resolve via `/proc/<pid>/cgroup`.
- Mounts (minimal): `/var/run/docker.sock` (intended for metadata) and a named volume
  for the alert log. No BTF / bpffs / `/proc` bind mounts are needed (no CO-RE;
  `/proc` comes from `pid:host`).
- Capabilities: runs as root with `cap_drop: ALL` + `cap_add` `SYS_ADMIN` (load eBPF),
  `SYS_PTRACE` (read `/proc/<pid>`), `NET_ADMIN` (network tracepoints) — a scoped set,
  not full `privileged: true`. (eBPF needs *effective* caps, which a non-root user
  wouldn't retain.)
