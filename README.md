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

## Detection engine

Findings are not judged in isolation. KernelWatch is **context- and
chain-aware**, which is what keeps the signal high and the noise low:

- **Process-lineage context** — the same binary (`sh`, `curl`, `apt`) is benign
  or malicious depending on who launched it. A shell from cron/the entrypoint is
  suppressed; one from a network-facing service (nginx, php-fpm…) is escalated as
  a likely RCE/web-shell.
- **Attack-chain correlation** — independent findings from the same container's
  process tree are correlated across a sliding window. When they span multiple
  MITRE ATT&CK kill-chain stages (e.g. *Execution → Discovery → Credential
  Access → Persistence*), KernelWatch emits **one consolidated, escalated
  "attack chain" incident** with a risk score, instead of a scatter of
  disconnected alerts. Incidents bypass rate/severity filtering so they are
  never dropped. Tune via `KW_CORRELATION_*` (see `.env.example`).
- **Whole-server (host) monitoring** — set `KW_MONITOR_HOST=true` to extend
  detection from containers to the **Docker host itself** (opt-in; zero impact
  when off). Adds host-specific rules (account manipulation, log tampering,
  `docker.sock` abuse, temp-dir execution, service-spawned host shells) and an
  SSH brute-force detector that tails the host auth log
  (`KW_AUTHLOG_ENABLED`). Every alert carries a `scope` of `host` or `container`;
  query host findings via `GET /api/v1/alerts?scope=host`. See
  [docs/en/detection-rules.md](docs/en/detection-rules.md#host-whole-server-monitoring).
- **False-positive suppression** — process-lineage context, config exceptions
  (`KW_DETECTION_EXCEPTIONS`), short-window deduplication, and per-container rate
  limiting. Structured, queryable operator suppression rules (narrowable by
  `scope`/`hostname` for fleets) are wired into the detector and managed through
  the REST API.

## Output formats / SIEM integration

Alerts and incidents are written to the JSON log and POSTed to the webhook in
the format selected by `KW_ALERT_FORMAT`:

- `native` *(default)* — enriched KernelWatch JSON with full MITRE ATT&CK
  tactic/technique and kill-chain phase.
- `ecs` — [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/)
  for drop-in ingestion by Elasticsearch / Kibana / Elastic Security and any
  ECS-aware SIEM. MITRE mappings populate the ECS `threat.*` fields;
  KernelWatch-specific extras live under the `kernelwatch.*` namespace.

## REST API

An authenticated, read/manage API to query the alert & incident history and to
manage false-positive suppressions at runtime. **Off by default** — set
`KW_API_ENABLED=true` (requires `KW_DB_ENABLED=true` for the data endpoints). It
binds to `127.0.0.1` by default and **every endpoint requires a Bearer token**
(constant-time compared); it never exposes any ability to stop monitoring or run
anything on the host.

```bash
TOKEN=$KW_API_TOKEN   # from your .env

# Recent high/critical findings, last 24h
curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8080/api/v1/alerts?severity=critical&since=24h&limit=50'

# Just the correlated attack-chain incidents
curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8080/api/v1/alerts?rule=attack_chain'

# Aggregate counts (by severity / rule / container)
curl -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:8080/api/v1/stats?since=24h'

# Mark a recurring false positive — the detector reloads within seconds
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"rule_id":"network_tool","container_name":"app","reason":"healthcheck curl"}' \
  http://127.0.0.1:8080/api/v1/suppressions

curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/suppressions
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/api/v1/suppressions/<id>
```

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | Liveness probe |
| GET | `/api/v1/alerts` | Bearer | Query history (`severity`, `container`, `rule`, `since`, `limit`) |
| GET | `/api/v1/stats` | Bearer | Aggregate counts over `since` |
| GET | `/api/v1/suppressions` | Bearer | List false-positive rules |
| POST | `/api/v1/suppressions` | Bearer | Add a rule (live-reloaded into the detector) |
| DELETE | `/api/v1/suppressions/{id}` | Bearer | Remove a rule |

`since` accepts a duration (`24h`, `30m`) or an RFC3339 timestamp.

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
│   ├── detector/detector.go   # rule-based, lineage-aware detection engine
│   ├── correlator/            # attack-chain correlation (risk + kill-chain)
│   ├── suppress/              # operator false-positive rule model
│   ├── storage/               # TimescaleDB persistence + query layer
│   ├── api/                   # authenticated REST API
│   └── alerter/alerter.go     # alert dispatch (log / webhook / Slack / ECS)
├── main.go                    # wires everything, main event loop
├── Dockerfile                 # multi-stage build
├── docker-compose.yml         # production-ready compose file
└── .env.example               # all configurable variables documented
```

## Roadmap

- [x] TimescaleDB integration for event history
- [x] MITRE ATT&CK enrichment + kill-chain correlation (attack-chain incidents)
- [x] Operator false-positive suppression
- [x] ECS output for SIEM ingestion
- [x] REST API (alerts / stats / suppressions)
- [ ] WebSocket live alert stream + dashboard UI
- [ ] Static profiler (pre-deploy image analysis with syft)
- [ ] Per-container behavioral baseline (ML autoencoder)
- [ ] Kubernetes DaemonSet support
