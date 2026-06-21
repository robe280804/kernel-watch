# Dashboard

KernelWatch ships an optional **web dashboard** — a small [Next.js](https://nextjs.org)
app (in [`dashboard/`](../../dashboard)) that gives you a visual view over the alert
history and lets you manage false-positive suppressions, instead of querying
TimescaleDB by hand or reading `alerts.json`.

It is a thin UI on top of the existing [REST API](configuration.md#rest-api): it does
**not** talk to the database directly and adds no new privileges to the daemon.

## Architecture

```
Browser ──> Next.js route handlers (BFF, holds KW_API_TOKEN) ──> KernelWatch REST API (Bearer)
```

The browser only ever calls the dashboard's own `/api/*` routes. Those **server-side**
handlers inject the `KW_API_TOKEN` Bearer header and proxy the KernelWatch API. The token
never reaches the browser, and the KernelWatch API stays bound to loopback.

## Prerequisites

The dashboard is useless without the daemon's API and database, so on the **daemon** set:

| Variable | Required value | Why |
|---|---|---|
| `KW_API_ENABLED` | `true` | Starts the REST API the dashboard reads. Off by default. |
| `KW_API_TOKEN` | a strong random value | Shared secret. Must be ≥16 chars and must **not** contain `changeme` (the daemon refuses to start otherwise). Generate one: `openssl rand -hex 32`. |
| `KW_DB_ENABLED` | `true` | The `/alerts` and `/stats` endpoints query TimescaleDB. Compose defaults this to `true`. |

The daemon **and** the dashboard read the same `KW_API_TOKEN`, so setting it once in
`.env` keeps them in sync (Compose passes it through to the dashboard service).

## Running it (Docker Compose)

The `dashboard` service is already wired into `docker-compose.yml`. From the repo root:

```bash
# 1. enable the API + set a strong token in .env
TOKEN=$(openssl rand -hex 32)
sed -i "s|^KW_API_TOKEN=.*|KW_API_TOKEN=$TOKEN|" .env
grep -q '^KW_API_ENABLED=' .env \
  && sed -i 's|^KW_API_ENABLED=.*|KW_API_ENABLED=true|' .env \
  || echo 'KW_API_ENABLED=true' >> .env

# 2. (re)create the daemon and dashboard so both pick up the values
docker compose up -d --build kernelwatch dashboard

# 3. confirm the API is listening and the dashboard is up
docker compose logs --tail=20 kernelwatch    # expect "REST API listening"
docker compose ps dashboard                  # expect "Up (healthy)"
```

### What the Compose service does

- `build: ./dashboard` — builds the Next.js standalone image.
- `network_mode: host` — required so the dashboard can reach the daemon's API on
  `127.0.0.1:8080` (the API binds host loopback, unreachable from a bridge network).
- Binds itself to `127.0.0.1:${DASHBOARD_PORT:-3000}` (`HOSTNAME=127.0.0.1`), so the UI
  is **loopback-only** — not exposed on the host's public interfaces.
- `mem_limit: 256m`, `restart: unless-stopped`, and a healthcheck that hits its own root page.

## Accessing it

Because the dashboard is bound to loopback on the server, you cannot reach it directly
from another machine — that is intentional (it can mutate suppressions, so it must not be
publicly exposed). Two options:

### SSH tunnel (recommended for day-to-day)

From your workstation, forward a local port to the server's loopback:

```bash
ssh -L 3000:127.0.0.1:3000 <user>@<server>
```

Keep the session open and browse <http://127.0.0.1:3000>. Closing the SSH session drops
the tunnel. If local port 3000 is busy, use another, e.g. `-L 8088:127.0.0.1:3000`, then
browse `http://127.0.0.1:8088`.

### Reverse proxy + TLS (for permanent access)

Put a reverse proxy (Caddy, nginx, Traefik) on the server terminating HTTPS and proxying
to `127.0.0.1:3000`. Keep the dashboard itself on loopback; only the proxy faces the
network. Gate it behind **its own authentication** (and ideally VPN / IP-allowlist) — the
dashboard can add and delete suppressions, so treat it as a control surface.

## What you can do from the dashboard

### Overview

Aggregate counts over a selectable time window (1h / 24h / 7d / 30d), served by
`/api/v1/stats`:

- **Total alerts** and a per-severity card row.
- Breakdown bars: **by severity**, **by scope** (host vs container), **by rule**, and
  **top containers**.

This is the at-a-glance "how noisy is my fleet, and where" view.

### Alerts & Incidents

A filterable table of the alert history (`/api/v1/alerts`). Filters: time window (`since`),
**scope**, **severity**, **container**, **rule**, and **limit**. Each row surfaces the
fields that separate a real finding from benign noise:

- timestamp (UTC), severity badge, scope badge (host/container)
- rule id, container name, **process name**, **parent name**
- the reason, plus the **command line** / `details` (e.g. the tool, the file touched)

Correlated **attack-chain incidents** (`rule_id = attack_chain`) appear here too — filter
by rule `attack_chain` to see only incidents.

### Suppressions

List, add, and delete the operator false-positive model (`/api/v1/suppressions`). This is
the **live-tunable "settings"** surface: changes take effect immediately because the daemon
hot-reloads the suppression set — no restart.

A suppression matches an alert only when **every** field you set matches (fields are ANDed,
so a more specific rule silences less). Set **at least one** primary field:

- `rule_id` (e.g. `network_tool`), `container_name`, `process_name`, or `substr`
  (case-insensitive match over name / image / cmdline / ancestry).
- `scope` and `hostname` only **narrow** an existing rule — they cannot stand alone (this
  prevents a blanket "silence all host alerts" rule).

**Example — silence a healthcheck `curl` that keeps firing `network_tool` on the host:**
on the Suppressions page set Rule ID `network_tool`, Process name `curl`, Scope `host`,
and a Reason note, then *Add*. The matching alerts (and any `attack_chain` incident built
from them) stop immediately.

> Suppressions are the right tool for false positives. For deeper tuning (thresholds,
> trusted parents, correlation scores, enabling host monitoring) edit the `KW_*` variables
> in `.env` and restart — see [configuration.md](configuration.md).

## Environment variables

Read by the dashboard service (see [configuration.md](configuration.md) for the full list):

| Variable | Default | Purpose |
|---|---|---|
| `KW_API_URL` | `http://127.0.0.1:8080` | Where the dashboard's server reaches the KernelWatch API. |
| `KW_API_TOKEN` | *(required)* | Bearer token; must match the daemon's `KW_API_TOKEN`. |
| `DASHBOARD_PORT` | `3000` | Port the dashboard listens on (bound to `127.0.0.1`). |

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `ERR_CONNECTION_REFUSED` in the browser | Nothing is listening at that address on **your** machine. You're browsing `127.0.0.1` on your workstation but the dashboard runs on the server — open the SSH tunnel above. |
| Page loads but charts show an **error banner** | The dashboard reached the server but the API didn't answer. Check `KW_API_ENABLED=true`, that the dashboard's `KW_API_TOKEN` matches the daemon's, and that the daemon logged `REST API listening`. |
| Charts load but are **empty** | No alerts in the selected window, or `KW_DB_ENABLED=false` (data endpoints return 503). Widen the window or enable persistence. |
| Daemon refuses to start after enabling the API | `KW_API_TOKEN` is missing, too short (<16 chars), or still contains `changeme`. Set a strong token. |

## Building / developing locally

```bash
cd dashboard
npm install
KW_API_URL=http://127.0.0.1:8080 KW_API_TOKEN=<token> npm run dev
```

See [`dashboard/README.md`](../../dashboard/README.md) for the file layout. The TypeScript
types in `dashboard/lib/types.ts` mirror the Go API shapes (`internal/alerter`,
`internal/storage`, `internal/suppress`) and should be kept in sync with them.
