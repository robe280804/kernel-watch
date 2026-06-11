# Deployment

## Requisiti

- **Kernel Linux 5.15+** (6.x consigliato) — servono ring-buffer + supporto alle
  mappe BTF-defined (standard sui kernel moderni).
- **Docker + Docker Compose**.
- Per le build da sorgente: `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`.

> Totalmente riproducibile: un `git clone` + `docker compose up -d --build` basta su
> **qualsiasi** host Linux. Il programma eBPF è self-contained (niente BTF host /
> `vmlinux.h`) e `go.sum` viene generato in build — niente `bpftool`, niente
> `go mod tidy` manuale.

> KernelWatch monitora il kernel Linux, quindi deve girare su un host Linux. Su
> Windows/macOS gira solo dentro una VM Linux (es. la VM di Docker Desktop), dove vede
> il kernel di quella VM — utile per i test, non un vero deploy su host.

## Avvio rapido (Docker Compose)

```bash
cp .env.example .env
# Imposta almeno KW_SERVER_NAME e un KW_API_TOKEN forte; configura le destinazioni
# degli alert (webhook/Slack) se le vuoi.

docker compose up -d --build
docker compose logs -f kernelwatch
```

## Cosa configura Compose

**Servizio `kernelwatch`**

- `network_mode: host` — vede tutta l'attività di rete dei container.
- `pid: "host"` — condivide il PID namespace dell'host così i PID host dell'eBPF si
  risolvono via `/proc/<pid>/cgroup` (senza, la risoluzione fallisce e nessun alert
  scatta).
- `cap_drop: ALL` + `cap_add: SYS_ADMIN, SYS_PTRACE, NET_ADMIN` con
  `privileged: false` — root con un set di capability ristretto (l'eBPF richiede
  capability effettive, che un utente non-root non manterrebbe).
- `security_opt: apparmor:unconfined` — richiesto per eBPF su alcune distro (Ubuntu).
- Mount (ridotti al minimo per portabilità):
  - `/var/run/docker.sock:ro` — metadati container (per il futuro arricchimento).
  - volume `kernelwatch-logs` — persiste `alerts.json`.
  - Nessun mount BTF / bpffs / `/proc` necessario (niente CO-RE; `/proc` arriva da
    `pid:host`).
- `healthcheck`: `pgrep kernelwatch`.
- `restart: unless-stopped`.

**Servizio `db` (TimescaleDB)**

- `timescale/timescaledb:latest-pg16`.
- Credenziali da `KW_DB_*`.
- `./migrations:/docker-entrypoint-initdb.d:ro` — l'SQL qui gira al **primo** avvio
  (`0001_alerts.sql` crea l'hypertable degli alert). L'app applica lo stesso schema
  in modo idempotente all'avvio, quindi anche i volumi esistenti sono coperti.
- Bindato solo su `127.0.0.1:5432` — non esporre mai Postgres su internet.

> Il demone salva gli **alert** su questo database quando `KW_DB_ENABLED=true`
> (Compose lo imposta). Lo store è best-effort — se il DB è giù KernelWatch continua
> a monitorare e il file di log resta il fallback durevole. Gli eventi syscall grezzi
> non vengono salvati. Interroga lo storico con
> `docker compose exec db psql -U kernelwatch -c "select timestamp,severity,rule_id,container_name,reason from alerts order by timestamp desc limit 20;"`.

## L'immagine Docker (multi-stage)

**Stage 1 — builder** (`golang:1.22-bookworm`)
1. Installa `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`.
2. `COPY go.mod go.sum* ./` + `go mod download` per il caching dei layer. `go.sum` è
   opzionale — viene generato in build se assente, quindi un checkout fresco non
   richiede `go mod tidy` manuale (committarlo resta consigliato per il pinning).
3. `go generate ./...` compila `ebpf/tracer.c` → `internal/collector/tracer_bpf*.go`.
   `tracer.c` è self-contained (struct kernel definita a mano), quindi niente
   `vmlinux.h` e niente BTF host a build time.
4. Costruisce un binario statico ripulito: `CGO_ENABLED=0 ... -ldflags="-s -w"`.

**Stage 2 — runtime** (`debian:bookworm-slim`)
1. Installa `libelf1`, `ca-certificates`.
2. Crea `/var/log/kernelwatch`.
3. Copia il binario. Gira come root (necessario per eBPF); i privilegi sono ristretti
   a un set di capability mirato da `docker-compose.yml`.

## Deploy su host aggiuntivi

L'obiettivo di design è **un'immagine, un `.env` per host**:

```bash
git clone <repo> && cd kernelwatch
cp .env.example .env
# modifica KW_SERVER_NAME, KW_API_TOKEN, destinazioni alert
docker compose up -d --build
```

## Build & run senza Docker

```bash
sudo apt install -y clang llvm libbpf-dev linux-libc-dev
go generate ./...    # compila eBPF → internal/collector/tracer_bpf*.go
go build -o kernelwatch .
sudo ./kernelwatch   # serve root per caricare eBPF
```

> `go generate` esegue la direttiva in `internal/collector/gen.go`, così lo
> scaffolding generato finisce nel package `collector`. Nessun `vmlinux.h` /
> `bpftool` e nessun `go.sum` preesistente richiesti.

La configurazione viene letta dall'ambiente del processo (esporta le variabili `KW_*`
o fai il source di un `.env`).

## Note operative

- **Capability vs. privileged:** alcuni kernel/distro potrebbero richiedere ulteriori
  allentamenti; se il load eBPF fallisce, controlla il lockdown del kernel e AppArmor.
- **Healthcheck:** l'healthcheck del container esegue `kernelwatch -health`, che
  passa solo quando il file di heartbeat del demone è recente (event loop vivo e in
  drenaggio) — più robusto di un controllo di esistenza del processo. Un demone
  bloccato o morto viene marcato unhealthy e riavviato.
- **Visibilità della perdita di eventi:** la riga di log `stats` periodica riporta
  `kernel_drops` (overflow del ring buffer), `channel_drops` (backpressure in
  userspace) e `enrich_miss_*` (processo terminato prima di poter leggere
  lineage/argv da `/proc`). Se `kernel_drops` cresce, aumenta `KW_EBPF_RINGBUF_SIZE`.
- **Crescita del log:** `alerts.json` ruota automaticamente a `KW_LOG_MAX_MB`
  mantenendo `KW_LOG_MAX_BACKUPS` file, così non può riempire il disco dell'host.
- **Limiti di risorse:** Compose limita il demone a `cpus: 1.0`, `mem_limit: 256m`,
  `pids_limit: 512` così non può mai affamare il carico reale dell'host — aumentali
  su host con volume di syscall molto elevato.
- **Consegna degli alert:** la consegna webhook/Slack riprova con backoff; ogni
  alert porta un `id` stabile per correlare un alert consegnato alla sua riga nel DB.
- **Immagine pinnata:** per deployment su flotta, scarica un tag rilasciato
  (`ghcr.io/<owner>/kernelwatch:<versione>`, prodotto dal workflow Release) invece di
  `build:`, così ogni host esegue un binario identico e precompilato.
- **Verificare che funzioni:** dopo `up`, esegui una shell in un *altro* container
  qualsiasi (`docker exec -it <c> sh`) e osserva comparire un alert
  `shell execution inside container` in `docker compose logs -f kernelwatch`.
