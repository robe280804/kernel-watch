# KernelWatch Dashboard

A small [Next.js](https://nextjs.org) (App Router) web UI over the KernelWatch
REST API. It shows alert/incident statistics, a filterable alert table, and a
suppressions manager (the live-tunable false-positive model).

## Architecture

```
Browser ──> Next.js route handlers (BFF, holds KW_API_TOKEN) ──> KernelWatch API (Bearer)
```

The browser only ever calls this app's own `/api/*` routes. Those server-side
handlers (`app/api/**`, backed by `lib/kw-client.ts`) inject the Bearer token and
proxy the KernelWatch REST API. **`KW_API_TOKEN` never reaches the browser.**

Pages:

- `/` — overview: totals + breakdowns (severity / scope / rule / top containers) from `/api/v1/stats`.
- `/alerts` — filterable alert & incident table (`since`, `scope`, `severity`, `container`, `rule`, `limit`).
- `/suppressions` — list / add / delete suppressions. Adds hot-reload the detector (no daemon restart).

## Prerequisites

The KernelWatch daemon must have the API enabled and persistence on:

```bash
KW_API_ENABLED=true
KW_DB_ENABLED=true
KW_API_TOKEN=<the same token the dashboard uses>
```

## Run with Docker Compose (recommended)

From the repo root, the `dashboard` service is already wired in `docker-compose.yml`:

```bash
docker compose up -d --build dashboard
```

It runs with `network_mode: host` so it can reach the API on `127.0.0.1:8080`, and
binds itself to `127.0.0.1:${DASHBOARD_PORT:-3000}`. Open <http://127.0.0.1:3000>.

> Loopback-only by design. For remote access, put it behind a reverse proxy with
> TLS and its own authentication — same posture as the REST API and database.

## Run locally (development)

```bash
cd dashboard
npm install
KW_API_URL=http://127.0.0.1:8080 KW_API_TOKEN=<token> npm run dev
```

## Environment

| Var | Default | Purpose |
|-----|---------|---------|
| `KW_API_URL` | `http://127.0.0.1:8080` | Where the server reaches the KernelWatch API |
| `KW_API_TOKEN` | *(required)* | Bearer token; must match the daemon's `KW_API_TOKEN` |
| `PORT` | `3000` | Port the dashboard listens on |
| `HOSTNAME` | `0.0.0.0` (compose sets `127.0.0.1`) | Bind address |

## Types

`lib/types.ts` mirrors the Go API shapes. Keep it in sync with:
`internal/alerter/alerter.go`, `internal/storage/query.go`, `internal/suppress/suppress.go`.
