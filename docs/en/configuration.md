# Configuration reference

All configuration is via **environment variables**, loaded and validated by
`internal/config/config.go`. There are no config files: deploy the same image
everywhere and change only the `.env`. Copy `.env.example` to `.env` to start.

## Variables

### Server identity & mode

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_SERVER_NAME` | string | `kernelwatch-host` | Human-readable host name; appears in every alert (`server_name`). |
| `KW_MODE` | enum | `alert` | `alert` evaluates rules and dispatches alerts; `monitor` is a dry-run (rules are evaluated and logged but webhook/Slack are never called). Validated. |

### Detection ruleset (YAML)

Detection rules are **data, not code**: a built-in ruleset is embedded in the
binary and these overlays merge on top of it (override an existing rule by id,
`append: true` to extend its tags/exceptions, or add new rules) — no recompile.
See [detection-rules.md](detection-rules.md) for the DSL. Validate a ruleset
without root or eBPF with `kernelwatch --validate` (ideal for CI).

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_RULES_FILE` | string | _(empty)_ | A single YAML overlay file merged on the defaults. Validated as a readable file. |
| `KW_RULES_DIR` | string | _(empty)_ | A directory of `*.yaml`/`*.yml` overlays, applied in lexical order. Validated as a directory. |

### Process-lineage detection tuning

Detection is context-aware: the same binary (`sh`, `curl`, `apt`) is benign or
malicious depending on its process ancestry.

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_ANCESTRY_DEPTH` | int | `5` | Ancestor processes to resolve per execve. Values `≤ 0` are ignored (default kept). |
| `KW_TRUSTED_PARENTS` | CSV | _(empty)_ | Extra parent process names treated as benign supervisors/schedulers, on top of the built-ins (init, systemd, cron, containerd-shim, tini…). |
| `KW_NETWORK_PARENTS` | CSV | _(empty)_ | Extra parent process names treated as network-facing (attack surface), on top of the built-ins (nginx, apache2, php-fpm, node, java…). |
| `KW_DETECTION_EXCEPTIONS` | CSV | _(empty)_ | Suppress any alert whose container name, image, cmdline, or ancestry contains one of these substrings. |

### Host (whole-server) monitoring

Opt-in. When `KW_MONITOR_HOST=false` (default) every host event is dropped at the
collector and behavior is identical to the container-only build. See
[detection-rules.md](detection-rules.md) for the host ruleset.

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_MONITOR_HOST` | bool | `false` | Extend detection from containers to the Docker host itself. |
| `KW_HOST_OPEN_WATCH_EXTRA` | CSV | _(empty)_ | Extra host `openat` path prefixes/substrings to watch, beyond the built-in security-relevant set. |
| `KW_HOST_EXEC_EXCLUDE` | CSV | _(empty)_ | Comm names to exclude from host execve monitoring (fleet agents like node_exporter, datadog-agent…). |
| `KW_HOST_TRUSTED_WRITERS` | CSV | _(empty)_ | Extra processes treated as trusted writers of host persistence/config paths (beyond dpkg/apt/rpm/dnf/snapd/systemd/cloud-init/logrotate/dockerd…). |
| `KW_HOST_TRUSTED_PARENTS` | CSV | _(empty)_ | Extra benign parent comms for host-scope classification only (merged on top of the container trusted-parents list). |
| `KW_HOST_DOCKER_CLIENTS` | CSV | _(empty)_ | Extra comm names allowed to open `/var/run/docker.sock` on the host without raising `host_docker_sock`. |

### Alert thresholds & format

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_ALERT_MIN_SEVERITY` | enum | `medium` | Minimum severity to emit: `low` / `medium` / `high` / `critical`. Validated. (Correlated incidents bypass this.) |
| `KW_ALERT_MAX_RATE` | int | `10` | Max alerts per container within the rate window. |
| `KW_ALERT_RATE_WINDOW` | int (s) | `60` | Sliding-window length for rate limiting. |
| `KW_ALERT_FORMAT` | enum | `native` | Wire format for the log file and webhook bodies: `native` (enriched KernelWatch JSON) or `ecs` (Elastic Common Schema). Slack always uses the human-readable format. Validated. |

### Attack-chain correlation

Independent findings from one container's process tree that span multiple MITRE
kill-chain stages within the window are consolidated into one escalated incident.
Correlated incidents bypass severity/rate filtering.

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_CORRELATION_ENABLED` | bool | `true` | Enable attack-chain correlation. |
| `KW_CORRELATION_WINDOW` | int (s) | `300` | Sliding window over which a container's findings are correlated. Values `≤ 0` ignored. |
| `KW_CORRELATION_MIN_STAGES` | int | `3` | Distinct kill-chain stages required to raise an incident. Values `≤ 0` ignored. |
| `KW_CORRELATION_MIN_SCORE` | int | `120` | OR: accumulated risk score required (risk points: low=10, medium=25, high=50, critical=100). Values `≤ 0` ignored. |
| `KW_CORRELATION_COOLDOWN` | int (s) | `300` | Minimum seconds between incidents for the same container (anti-flap). Values `< 0` ignored. |
| `KW_CORRELATION_HOST_MIN_STAGES` | int | `0` (inherit) | Host-bucket override for min stages. `0` = inherit the container value. |
| `KW_CORRELATION_HOST_MIN_SCORE` | int | `0` (inherit) | Host-bucket override for min score. `0` = inherit the container value. |

### SSH brute-force detection (auth-log tailer)

eBPF cannot see authentication outcomes, so SSH credential-stuffing is detected by
tailing the host auth log. Opt-in. Synthesizes host-scope `ssh_bruteforce` alerts
(MITRE T1110.001).

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_AUTHLOG_ENABLED` | bool | `false` | Enable the auth-log tailer. |
| `KW_AUTHLOG_PATH` | string | `/var/log/auth.log` | Auth log to tail (Debian/Ubuntu `auth.log`, RHEL/CentOS `secure`; in Docker mount the host log read-only). |
| `KW_SSH_BRUTE_THRESHOLD` | int | `5` | Failed attempts from one source IP within the window before alerting. Values `≤ 0` ignored. |
| `KW_SSH_BRUTE_WINDOW` | int (s) | `60` | Sliding window for brute-force counting. Values `≤ 0` ignored. |

### Alert destinations

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_LOG_ENABLED` | bool | `true` | Write alerts to the JSON log file. |
| `KW_LOG_PATH` | string | `/var/log/kernelwatch/alerts.json` | Alert log path (directory auto-created). |
| `KW_LOG_MAX_MB` | int | `50` | Rotate the alert log past this size; `0` disables rotation. |
| `KW_LOG_MAX_BACKUPS` | int | `3` | Rotated backups to keep (`alerts.json.1…N`). |
| `KW_WEBHOOK_ENABLED` | bool | `false` | Enable webhook delivery. |
| `KW_WEBHOOK_URL` | string | — | Webhook endpoint. **Required** if webhook enabled. |
| `KW_WEBHOOK_SECRET` | string | — | HMAC-SHA256 signing key. If empty, requests are unsigned. |
| `KW_SLACK_ENABLED` | bool | `false` | Enable Slack delivery. |
| `KW_SLACK_WEBHOOK_URL` | string | — | Slack incoming webhook. **Required** if Slack enabled. |
| `KW_SLACK_CHANNEL` | string | `#security-alerts` | Slack channel. |

### REST API

Authenticated read/manage API for the alert & incident history and operator
suppressions. Off by default (opt-in network surface); data endpoints require
`KW_DB_ENABLED=true`. See [README.md](../../README.md) for the endpoint list.

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_API_ENABLED` | bool | `false` | Expose the REST API. |
| `KW_API_BIND_ADDR` | string | `127.0.0.1` | Interface to bind. **Keep loopback** unless you front it with TLS + network controls — it is plain HTTP. |
| `KW_API_PORT` | int | `8080` | REST API port. Validated 1–65535. |
| `KW_API_TOKEN` | string | — | Bearer token. **Required when `KW_API_ENABLED=true`**: ≥16 chars, must not contain `changeme`. Compared in constant time. |

### eBPF, health & database

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_EBPF_RINGBUF_SIZE` | int (bytes) | `16777216` (16 MB) | Ring-buffer size, applied at eBPF load. Power of two, multiple of page size. Raise if `kernel_drops` climbs in the stats log. |
| `KW_HEALTH_FILE` | string | `/var/log/kernelwatch/health` | Heartbeat file written by the daemon and checked by `kernelwatch -health`. |
| `KW_DB_ENABLED` | bool | `false` | Persist alerts to TimescaleDB. docker-compose sets it `true`. Best-effort: a down DB never blocks monitoring. |
| `KW_DB_RETENTION_DAYS` | int | `90` | Auto-drop alerts older than N days (TimescaleDB retention). `0` = keep forever. |
| `KW_DB_HOST` | string | `localhost` | TimescaleDB host. |
| `KW_DB_PORT` | int | `5432` | TimescaleDB port. |
| `KW_DB_NAME` | string | `kernelwatch` | Database name. |
| `KW_DB_USER` | string | `kernelwatch` | Database user. |
| `KW_DB_PASSWORD` | string | — | Database password. **Required when `KW_DB_ENABLED=true`; the daemon refuses to start if empty or left as `changeme`.** |
| `KW_DB_SSL_MODE` | string | `disable` | `sslmode` for the DSN. |

> CSV values are split on commas and trimmed; empty entries are dropped. Booleans
> use Go's `strconv.ParseBool` (`true/false/1/0/t/f`…); an unparseable value falls
> back to the default. Integers that fail to parse also fall back to the default
> (the bad value is reported but non-fatal).

## Validation rules (`Config.validate`)

Loading **fails** (process exits) if any of these is violated:

- `KW_ALERT_MIN_SEVERITY` is not one of `low/medium/high/critical`.
- `KW_MODE` is not `alert` or `monitor`.
- `KW_ALERT_FORMAT` is not `native` or `ecs`.
- `KW_DB_ENABLED=true` but `KW_DB_PASSWORD` is empty or left as `changeme`.
- `KW_API_PORT` is outside 1–65535.
- `KW_API_ENABLED=true` but `KW_API_TOKEN` is empty, shorter than 16 characters,
  or contains `changeme`.
- `KW_RULES_FILE` is set but is not a readable file.
- `KW_RULES_DIR` is set but is not a directory.
- `KW_WEBHOOK_ENABLED=true` but `KW_WEBHOOK_URL` is empty.
- `KW_SLACK_ENABLED=true` but `KW_SLACK_WEBHOOK_URL` is empty.

## Filtering behaviour (`Config.IsMonitored`)

```
if name in blacklist           → NOT monitored
else if whitelist is non-empty → monitored only if name in whitelist
else                           → monitored
```

Matching is case-insensitive. The container "name" passed here is what the mapper
resolved — currently the **12-char short container ID** (because `dockerInspect`
is a stub), so name-based whitelisting/blacklisting only works reliably once
Docker-API enrichment is implemented.

## Database DSN

`Config.DSN()` produces:

```
host=<H> port=<P> dbname=<N> user=<U> password=<PW> sslmode=<M>
```

The storage layer (`internal/storage`) and the REST API both use this DSN when
`KW_DB_ENABLED=true`.

## Security notes

- `KW_WEBHOOK_SECRET`, `KW_API_TOKEN` and `KW_DB_PASSWORD` are plaintext env vars.
  For production prefer Docker/Swarm secrets or a secrets manager and inject at
  runtime rather than committing a real `.env`.
- The Compose file binds Postgres to `127.0.0.1:5432` only — keep it that way.
- The REST API binds to `127.0.0.1` by default and **refuses to start** without a
  strong `KW_API_TOKEN` (≥16 chars, no `changeme`) when enabled — there is no
  "auth disabled" mode. It is plain HTTP, so only set `KW_API_BIND_ADDR` to a
  non-loopback address behind a TLS-terminating reverse proxy and network controls.
