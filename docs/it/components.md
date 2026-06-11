# Componenti — riferimento file per file

Ogni file sorgente, cosa fa, e i suoi tipi/funzioni principali.

---

## `main.go`

**Ruolo:** Entry point e orchestratore.

Flusso:
1. Configura il logging JSON strutturato via `slog` a livello `Info`.
2. `config.Load()` — fallisce subito su configurazione non valida.
3. Costruisce i componenti: `container.New(5*time.Minute)` (mapper), `alerter.New(cfg)`,
   `detector.New()`, `collector.New(cfg, mapper)`.
4. `coll.Start()` restituisce il canale eventi; in caso di errore stampa il
   suggerimento *"run as root (or with CAP_SYS_ADMIN) on Linux kernel 5.15+"*
   ed esce.
5. Installa un `signal.NotifyContext` per SIGINT/SIGTERM.
6. **Event loop:** per ogni evento, `detect.Check(event)`; se restituisce un alert,
   `alert.Send(a)`. Logga le statistiche `processed`/`alerted` ogni 10.000 eventi.
   Esce in modo pulito quando il canale si chiude o arriva un segnale.

> La direttiva `//go:generate` per l'eBPF è in `internal/collector/gen.go` (non qui),
> così lo scaffolding generato finisce nel package `collector`.

---

## `ebpf/tracer.c`

**Ruolo:** Programma nello spazio kernel. Compilato da `go generate` (bpf2go) — nota il
tag `//go:build ignore` così che la toolchain Go lo salti durante le build normali.

- Definisce `struct event` (deve combaciare con `RawEvent`; vedi
  [architecture.md](architecture.md)).
- Dichiara la mappa ring-buffer `events` (`BPF_MAP_TYPE_RINGBUF`, `max_entries =
  1<<24` = 16 MB).
- `fill_common(e, type)` — popola PID/TID/UID/tipo/timestamp/`comm` per ogni evento
  usando `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`, `bpf_ktime_get_ns`,
  `bpf_get_current_comm`.
- Quattro programmi tracepoint:
  - `trace_execve` (`sys_enter_execve`) — legge `args[0]` (filename) con
    `bpf_probe_read_user_str`.
  - `trace_openat` (`sys_enter_openat`) — legge `args[1]` (percorso).
  - `trace_connect` (`sys_enter_connect`) — legge la `sockaddr_in` da `args[1]`;
    registra porta e indirizzo solo per `AF_INET` (IPv4, family == 2).
  - `trace_clone` (`sys_enter_clone`) — solo campi comuni.
- `LICENSE[] = "GPL"` — richiesto per usare gli helper BPF GPL-only.

> Il commento nel kernel per `openat` dice che il filtraggio è demandato allo spazio
> utente — il kernel registra tutte le open, e `isNoisyPath` le filtra in `collector.go`.

---

## `internal/config/config.go`

**Ruolo:** Caricare e validare tutta la configurazione di runtime dalle variabili
d'ambiente `KW_*`. Non esistono file di configurazione.

- Struct `Config` — ogni campo mappa 1:1 una variabile `KW_*` (vedi
  [configuration.md](configuration.md)).
- `Load()` — applica i default, poi sovrascrive dall'env, poi `validate()`.
- `validate()` — verifica `AlertMinSeverity ∈ {low,medium,high,critical}`, `APIPort`
  in 1–65535, e che un URL sia presente quando webhook/Slack sono abilitati.
- `IsMonitored(name)` — la blacklist vince; se è impostata una whitelist solo i suoi
  membri sono monitorati; altrimenti è monitorato tutto ciò che non è in blacklist.
  Case-insensitive.
- `DSN()` — costruisce la stringa di connessione PostgreSQL (usata quando arriverà la
  persistenza).
- Helper: `envOr`, `envInt`, `envBool`, `splitCSV`.

> Nota: alcuni campi nel codice attuale sono impostati solo da default/env; la
> dimensione del ring buffer viene letta in `cfg.EBPFRingbufSize` ma non applicata al
> momento del load eBPF (vedi [roadmap.md](roadmap.md)).

---

## `internal/collector/collector.go`

**Ruolo:** Il ponte tra kernel e spazio utente.

- `RawEvent` — rispecchia esattamente la struct C (layout-critico).
- `Event` — l'evento arricchito e analizzato (stringhe, `net.IP`, `time.Time`, più
  `*container.Info`). `TypeName()` mappa il byte del tipo su `execve/open/connect/
  clone/unknown`.
- `Collector` — contiene config, mapper, i `tracerObjects` generati, i `links`
  agganciati e il `ringbuf.Reader`.
- `New(cfg, mapper)` — costruttore; non carica ancora nulla.
- `Start()` —
  1. `rlimit.RemoveMemlock()` (le mappe eBPF richiedono la rimozione del lock),
  2. `loadTracerObjects(...)` (generato da bpf2go),
  3. aggancia i quattro tracepoint (`link.Tracepoint`),
  4. apre il reader del ring buffer,
  5. avvia `readLoop` e restituisce il canale bufferizzato (cap 1000).
- `Stop()` / `cleanup()` — chiude il reader, sgancia i link, chiude gli oggetti.
- `readLoop(out)` — read → decode → `parseEvent` → arricchimento via mapper →
  filtro (monitorato? percorso rumoroso?) → invio non bloccante. `defer close(out)`
  segnala lo shutdown a `main`.
- Helper: `cstring` (byte null-terminati → stringa), `isNoisyPath`.

> Particolarità: `loadTracerObjects` viene chiamato con `CollectionOptions` il cui
> commento dice "override ring buffer size from config", ma nessun override della
> dimensione viene effettivamente eseguito (solo `PinPath: ""`).

---

## `internal/container/mapper.go`

**Ruolo:** Risolvere un PID in metadati container Docker, con caching.

- `Info` — `ID` (64 char), `ShortID` (12), `Name`, `ImageName`, `ResolvedAt`.
- `Mapper` — cache PID→`*Info` (`nil` indica processo host) protetta da `RWMutex`, con
  un TTL e un `evictLoop` in background (ogni 30 s).
- `Resolve(pid)` — lookup in cache, altrimenti `resolveFromProc`.
- `resolveFromProc(pid)` — legge `/proc/<pid>/cgroup`; un file mancante (processo
  terminato) è trattato come "host", non come errore.
- `extractContainerID(cgroup)` — analizza sia cgroup **v1** (`/docker/<64hex>`) sia
  **v2** (`docker-<64hex>.scope`), validando 64 caratteri esadecimali.
- `dockerInspect(id)` — **stub**: restituisce sempre `not implemented`; quindi `Name`
  ripiega sullo short ID di 12 caratteri e `ImageName` resta vuoto.
- `Invalidate(pid)` — rimuove un PID dalla cache.
- `ParseDockerList(data)` — analizza `GET /containers/json` in una mappa indicizzata
  per ID completo e short. Helper per il futuro arricchimento via Docker API; **non
  ancora collegato**.
- `isHex` — helper di validazione esadecimale.

---

## `internal/detector/detector.go`

**Ruolo:** Motore di detection basato su regole.

- `Rule` — `func(collector.Event) *alerter.Alert`.
- `Detector` — contiene il set di regole ordinato costruito in `New()`.
- `Check(event)` — restituisce `nil` per gli eventi host; altrimenti esegue le regole
  in ordine e restituisce il **primo** alert, marcando i campi container/processo/
  syscall/timestamp.
- Sei regole (dettaglio completo in [detection-rules.md](detection-rules.md)):
  `ruleShellInContainer`, `rulePrivilegedProcessInContainer`,
  `ruleSensitiveFileAccess`, `ruleUnexpectedNetworkTool`,
  `rulePackageManagerInContainer`, `ruleCredentialFileAccess`.

> Comportamento da conoscere: solo la prima regola che matcha scatta per evento, e il
> matching è per nome processo esatto (`comm`, in minuscolo) per le regole exec e per
> prefisso di percorso per le regole sui file.

---

## `internal/alerter/alerter.go`

**Ruolo:** Formattare e smistare gli alert; applicare soglia di severità e rate limit.

- Costanti `Severity` + `severityRank` per i confronti di soglia.
- `Alert` — il payload dell'alert serializzabile in JSON (id, rule id, server,
  timestamp, severità, id/nome container, immagine, syscall, pid, processo,
  **parent/genealogia, cmdline**, reason, details, MITRE TTP/tactic, tag).
- `AlertSink` — interfaccia opzionale di persistenza (`Save(*Alert)`), implementata
  da `internal/storage`; iniettata da `main` così l'alerter evita un ciclo di import.
- `Alerter` — config, handle del file di log, client HTTP (timeout 5 s), sink
  opzionale e stato del rate-limit per container.
- `New(cfg, sink)` — apre/crea il file di log; `sink` può essere nil (DB disabilitato).
- `Send(alert)` — filtro severità → rate limit → marcatura server/timestamp → log
  (sincrono) → **persistenza via sink** → (solo in modalità `alert`) goroutine
  webhook + Slack. Persistenza e log girano anche in modalità `monitor` (dry-run).
- `writeLog` — appende JSON delimitato da newline al file **e** emette un `slog.Warn`
  strutturato.
- `sendWebhook` — invia JSON in POST; se `KW_WEBHOOK_SECRET` è impostato, aggiunge un
  header `X-KernelWatch-Signature: sha256=<hmac>` (HMAC-SHA256 del body).
- `sendSlack` — costruisce un messaggio Slack Block-Kit con un'emoji di severità e la
  riga MITRE.
- `isRateLimited(containerID)` — finestra scorrevole: elimina i timestamp più vecchi
  della finestra, blocca se il conteggio raggiunge `AlertMaxRate`, altrimenti registra
  "adesso".

---

## `internal/storage/postgres.go`

**Ruolo:** Salvare gli alert su TimescaleDB — un `AlertSink` asincrono e resiliente.

- `Store` — canale bufferizzato (cap 2000) + un worker in background che raggruppa
  (≤100 alert o ogni 2 s) e inserisce con un singolo `pgx.Batch`/`SendBatch`.
- `Save(*Alert)` — **non bloccante**: accoda, oppure scarta-e-conta quando il buffer
  è pieno, così l'event loop non viene mai bloccato da un DB lento/non raggiungibile.
- `ensureSchema` — DDL idempotente (estensione, hypertable `alerts`, indici,
  `add_retention_policy` da `KW_DB_RETENTION_DAYS`), ritentato finché il DB è pronto.
- interfaccia `inserter` — astrae Postgres così la logica di buffering/batching è
  testabile offline (senza un DB reale) in `postgres_test.go`.
- `Close()` — svuota il buffer (timeout limitato) e chiude il pool.
- Driver: `github.com/jackc/pgx/v5` (+ `pgxpool`); DSN da `Config.DSN()`.

---

## File di build & deploy

- **`go.mod`** — modulo `kernelwatch`, Go 1.22, unica require:
  `github.com/cilium/ebpf v0.15.0`. (Nessun `go.sum` ancora committato; il `COPY
  go.sum` e il `go mod download` del Dockerfile lo richiederanno.)
- **`Dockerfile`** — multi-stage: builder (`golang:1.22-bookworm` + clang/LLVM/libelf/
  header, esegue `go generate`, costruisce un binario statico ripulito) → runtime
  (`debian:bookworm-slim` + libelf, utente non-root UID 1000). Vedi
  [deployment.md](deployment.md).
- **`docker-compose.yml`** — il demone `kernelwatch` (rete host, capability mirate,
  mount host, healthcheck) più un servizio `timescaledb` (`./migrations` eseguito
  automaticamente al primo avvio, bindato solo su localhost).
- **`.env.example`** — template documentato di ogni variabile `KW_*`.
- **`README.md`** — readme di progetto top-level.
- **`docs/`** — questa documentazione (`en/` e `it/`).
