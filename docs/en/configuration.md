# Configuration reference

All configuration is via **environment variables**, loaded and validated by
`internal/config/config.go`. There are no config files: deploy the same image
everywhere and change only the `.env`. Copy `.env.example` to `.env` to start.

## Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `KW_SERVER_NAME` | string | `kernelwatch-host` | Human-readable host name; appears in every alert (`server_name`). |
| `KW_CONTAINER_WHITELIST` | CSV | _(empty = all)_ | If set, **only** these container names are monitored. |
| `KW_CONTAINER_BLACKLIST` | CSV | _(empty)_ | Container names to ignore. Blacklist always wins over whitelist. |
| `KW_ALERT_MIN_SEVERITY` | enum | `medium` | Minimum severity to emit: `low` / `medium` / `high` / `critical`. Validated. |
| `KW_ALERT_MAX_RATE` | int | `10` | Max alerts per container within the rate window. |
| `KW_ALERT_RATE_WINDOW` | int (s) | `60` | Sliding-window length for rate limiting. |
| `KW_LOG_ENABLED` | bool | `true` | Write alerts to the JSON log file. |
| `KW_LOG_PATH` | string | `/var/log/kernelwatch/alerts.json` | Alert log path (directory auto-created). |
| `KW_LOG_MAX_MB` | int | `50` | Rotate the alert log past this size; `0` disables rotation. |
| `KW_LOG_MAX_BACKUPS` | int | `3` | Rotated backups to keep (`alerts.json.1…N`). |
| `KW_HEALTH_FILE` | string | `/var/log/kernelwatch/health` | Heartbeat file written by the daemon and checked by `kernelwatch -health`. |
| `KW_WEBHOOK_ENABLED` | bool | `false` | Enable webhook delivery. |
| `KW_WEBHOOK_URL` | string | — | Webhook endpoint. **Required** if webhook enabled. |
| `KW_WEBHOOK_SECRET` | string | — | HMAC-SHA256 signing key. If empty, requests are unsigned. |
| `KW_SLACK_ENABLED` | bool | `false` | Enable Slack delivery. |
| `KW_SLACK_WEBHOOK_URL` | string | — | Slack incoming webhook. **Required** if Slack enabled. |
| `KW_SLACK_CHANNEL` | string | `#security-alerts` | Slack channel. |
| `KW_API_PORT` | int | `8080` | REST API port. Validated 1–65535. *(API not implemented yet.)* |
| `KW_API_TOKEN` | string | — | Bearer token for the future API. |
| `KW_EBPF_RINGBUF_SIZE` | int (bytes) | `16777216` (16 MB) | Ring-buffer size, applied at eBPF load. Power of two, multiple of page size. Raise if `kernel_drops` climbs in the stats log. |
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
> back to the default.

## Validation rules (`Config.validate`)

Loading **fails** (process exits) if any of these is violated:

- `KW_ALERT_MIN_SEVERITY` is not one of `low/medium/high/critical`.
- `KW_API_PORT` is outside 1–65535.
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

It is ready for use but no component opens a DB connection yet.

## Security notes

- `KW_WEBHOOK_SECRET`, `KW_API_TOKEN` and `KW_DB_PASSWORD` are plaintext env vars.
  For production prefer Docker/Swarm secrets or a secrets manager and inject at
  runtime rather than committing a real `.env`.
- The Compose file binds Postgres to `127.0.0.1:5432` only — keep it that way.
- Set a strong, random `KW_API_TOKEN` before the API ships; an empty token is
  meant to mean "auth disabled" (not recommended).
