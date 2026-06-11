# KernelWatch

eBPF-based Host Intrusion Detection System for Docker containers.
Monitors syscalls at kernel level — zero agents inside containers.

## Requirements

- Linux kernel 5.15+ (6.x recommended)
- Docker + Docker Compose
- For source builds: `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`

> Fully reproducible: `git clone` + `docker compose up -d --build` is enough on any
> Linux host — the eBPF program is self-contained (no host BTF / `vmlinux.h`).

## Quick start

```bash
# 1. Clone and configure
git clone https://github.com/youruser/kernelwatch
cd kernelwatch
cp .env.example .env
# Edit .env — at minimum set KW_SERVER_NAME and KW_API_TOKEN

# 2. Build and run
docker compose up -d --build

# 3. Watch alerts in real time
docker compose logs -f kernelwatch
```

## Configuration

All configuration is via environment variables (see `.env.example`).
No config files — deploy the same image to any server, change only the `.env`.

| Variable | Default | Description |
|---|---|---|
| `KW_SERVER_NAME` | `kernelwatch-host` | Human-readable name for this host |
| `KW_CONTAINER_WHITELIST` | _(empty = all)_ | Comma-separated containers to monitor |
| `KW_CONTAINER_BLACKLIST` | `kernelwatch,portainer` | Containers to ignore |
| `KW_ALERT_MIN_SEVERITY` | `medium` | Minimum severity: low / medium / high / critical |
| `KW_ALERT_MAX_RATE` | `10` | Max alerts per container per window |
| `KW_ALERT_RATE_WINDOW` | `60` | Rate window in seconds |
| `KW_LOG_ENABLED` | `true` | Write alerts to JSON log file |
| `KW_LOG_PATH` | `/var/log/kernelwatch/alerts.json` | Alert log path |
| `KW_WEBHOOK_ENABLED` | `false` | Send alerts to webhook |
| `KW_WEBHOOK_URL` | — | Webhook endpoint URL |
| `KW_WEBHOOK_SECRET` | — | HMAC-SHA256 signing secret |
| `KW_SLACK_ENABLED` | `false` | Send alerts to Slack |
| `KW_SLACK_WEBHOOK_URL` | — | Slack incoming webhook URL |
| `KW_SLACK_CHANNEL` | `#security-alerts` | Slack channel |
| `KW_API_PORT` | `8080` | REST API port |
| `KW_API_TOKEN` | — | Bearer token for API auth |

## Detection rules

| Rule | Severity | MITRE TTP |
|---|---|---|
| Shell execution inside container | High | T1059 |
| Privilege escalation tool (sudo, nsenter…) | High | T1548 |
| Docker socket accessed by container | Critical | T1611 |
| Sensitive file access (/etc/shadow, /root/.ssh…) | Medium | T1005 |
| Network tool execution (nmap, nc…) | Medium–High | T1046 |
| Package manager inside running container | Medium | T1072 |
| Credential file access (.env, .aws/credentials…) | High | T1552 |

## Deploy to a new server

```bash
# On the new server
git clone https://github.com/youruser/kernelwatch
cd kernelwatch
cp .env.example .env
nano .env  # set KW_SERVER_NAME, KW_API_TOKEN, alert destinations
docker compose up -d --build
```

That's it. Same image, different `.env`.

## Build from source (without Docker)

```bash
# Install build deps
sudo apt install -y clang llvm libelf-dev linux-headers-$(uname -r)

# Generate eBPF bytecode
go generate ./...

# Build
go build -o kernelwatch .

# Run (requires root for eBPF)
sudo ./kernelwatch
```

## Project structure

```
kernelwatch/
├── ebpf/tracer.c              # eBPF program (kernel space) — hooks syscalls
├── internal/
│   ├── config/config.go       # env var loading + validation
│   ├── collector/collector.go # loads eBPF, reads ring buffer, parses events
│   ├── container/mapper.go    # PID → container ID via /proc cgroup
│   ├── detector/detector.go   # rule-based detection engine
│   └── alerter/alerter.go     # alert dispatch (log / webhook / Slack)
├── main.go                    # wires everything, main event loop
├── Dockerfile                 # multi-stage build
├── docker-compose.yml         # production-ready compose file
└── .env.example               # all configurable variables documented
```

## Roadmap

- [ ] Static profiler (pre-deploy image analysis with syft)
- [ ] Per-container behavioral baseline (ML autoencoder)
- [ ] REST API + WebSocket dashboard
- [ ] TimescaleDB integration for event history
- [ ] Kubernetes DaemonSet support
- [ ] MITRE ATT&CK enrichment for all rules
