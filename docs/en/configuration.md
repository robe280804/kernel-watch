# Configuration reference

All configuration is via **environment variables**, loaded and validated by
`internal/config/config.go`. There are no config files: deploy the same image
everywhere and change only the `.env`. Copy `.env.example` to `.env` to start.

## Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `CS_SERVER_NAME` | string | `containersentry-host` | Human-readable host name; appears in every alert (`server_name`). |
| `CS_CONTAINER_WHITELIST` | CSV | _(empty = all)_ | If set, **only** these container names are monitored. |
| `CS_CONTAINER_BLACKLIST` | CSV | _(empty)_ | Container names to ignore. Blacklist always wins over whitelist. |
| `CS_ALERT_MIN_SEVERITY` | enum | `medium` | Minimum severity to emit: `low` / `medium` / `high` / `critical`. Validated. |
| `CS_ALERT_MAX_RATE` | int | `10` | Max alerts per container within the rate window. |
| `CS_ALERT_RATE_WINDOW` | int (s) | `60` | Sliding-window length for rate limiting. |
| `CS_LOG_ENABLED` | bool | `true` | Write alerts to the JSON log file. |
| `CS_LOG_PATH` | string | `/var/log/containersentry/alerts.json` | Alert log path (directory auto-created). |
| `CS_WEBHOOK_ENABLED` | bool | `false` | Enable webhook delivery. |
| `CS_WEBHOOK_URL` | string | — | Webhook endpoint. **Required** if webhook enabled. |
| `CS_WEBHOOK_SECRET` | string | — | HMAC-SHA256 signing key. If empty, requests are unsigned. |
| `CS_SLACK_ENABLED` | bool | `false` | Enable Slack delivery. |
| `CS_SLACK_WEBHOOK_URL` | string | — | Slack incoming webhook. **Required** if Slack enabled. |
| `CS_SLACK_CHANNEL` | string | `#security-alerts` | Slack channel. |
| `CS_API_PORT` | int | `8080` | REST API port. Validated 1–65535. *(API not implemented yet.)* |
| `CS_API_TOKEN` | string | — | Bearer token for the future API. |
| `CS_EBPF_RINGBUF_SIZE` | int (bytes) | `16777216` (16 MB) | Ring-buffer size. *(Read into config but not yet applied at load — see roadmap.)* |
| `CS_DB_HOST` | string | `localhost` | TimescaleDB host. |
| `CS_DB_PORT` | int | `5432` | TimescaleDB port. |
| `CS_DB_NAME` | string | `containersentry` | Database name. |
| `CS_DB_USER` | string | `containersentry` | Database user. |
| `CS_DB_PASSWORD` | string | — | Database password. |
| `CS_DB_SSL_MODE` | string | `disable` | `sslmode` for the DSN. |

> CSV values are split on commas and trimmed; empty entries are dropped. Booleans
> use Go's `strconv.ParseBool` (`true/false/1/0/t/f`…); an unparseable value falls
> back to the default.

## Validation rules (`Config.validate`)

Loading **fails** (process exits) if any of these is violated:

- `CS_ALERT_MIN_SEVERITY` is not one of `low/medium/high/critical`.
- `CS_API_PORT` is outside 1–65535.
- `CS_WEBHOOK_ENABLED=true` but `CS_WEBHOOK_URL` is empty.
- `CS_SLACK_ENABLED=true` but `CS_SLACK_WEBHOOK_URL` is empty.

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

- `CS_WEBHOOK_SECRET`, `CS_API_TOKEN` and `CS_DB_PASSWORD` are plaintext env vars.
  For production prefer Docker/Swarm secrets or a secrets manager and inject at
  runtime rather than committing a real `.env`.
- The Compose file binds Postgres to `127.0.0.1:5432` only — keep it that way.
- Set a strong, random `CS_API_TOKEN` before the API ships; an empty token is
  meant to mean "auth disabled" (not recommended).
