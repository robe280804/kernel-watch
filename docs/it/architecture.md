# Architettura

## Componenti

ContainerSentry è un singolo binario Go costruito da cinque package interni più il
programma eBPF. Ogni package ha una responsabilità chiara.

```
main.go ──────────── collega tutto, possiede l'event loop
│
├── internal/config     (config.go)     env vars → Config validata
├── internal/container  (mapper.go)      PID → Info container (parsing cgroup + cache)
├── internal/collector  (collector.go)   carica eBPF, legge ring buffer, parse + arricchimento
├── internal/detector   (detector.go)    esegue le regole sugli eventi → Alert
└── internal/alerter    (alerter.go)     smista gli alert (log/webhook/Slack) + rate limit

ebpf/tracer.c ──────── hook syscall nello spazio kernel → ring buffer
```

### Direzione delle dipendenze

```
config  ◄──── tutti leggono la config
container (mapper)  ◄──── il collector lo usa per arricchire gli eventi
collector  ──── produce collector.Event, importa container + config
detector  ──── importa collector (Event) e alerter (Alert)
alerter  ──── importa config; definisce il tipo Alert
main  ──── importa tutti i precedenti
```

`alerter.Alert` è il tipo di output condiviso: il detector lo costruisce, l'alerter
lo invia. `collector.Event` è il tipo di input condiviso che il detector consuma.

## Flusso dati end-to-end

1. **Cattura kernel** — Un processo container effettua una syscall. Il tracepoint
   corrispondente in `tracer.c` scatta, riserva uno slot nel ring buffer, riempie una
   `struct event` (PID, PPID, UID, tipo, `comm`, filename, porta/IP dest, timestamp) e
   la sottomette.

2. **Lettura e parsing** — `collector.readLoop()` si blocca su `reader.Read()`. Ogni
   record viene decodificato in binario (little-endian) in un `RawEvent`, poi
   convertito in un `Event` arricchito (`parseEvent`): stringhe C null-terminate →
   stringhe Go, l'IPv4 grezzo `uint32` → `net.IP`, timestamp in nanosecondi →
   `time.Time`.

3. **Arricchimento container** — `mapper.Resolve(pid)` restituisce l'`Info` del
   container o `nil` per i processi host. Il risultato è messo in cache per PID (anche
   `nil` è cachato).

4. **Filtraggio** — Due uscite anticipate in `readLoop`:
   - Se l'evento appartiene a un container **non monitorato** (`config.IsMonitored` →
     blacklist/whitelist), viene scartato.
   - Se è un `open` su un **percorso rumoroso** (`/proc/`, `/sys/`, `/dev/null`,
     `/dev/urandom`, `/etc/localtime`, `/usr/share/zoneinfo`), viene scartato.
   Gli eventi sopravvissuti vengono inviati su un **canale bufferizzato (capacità
   1000)**. Se il canale è pieno l'evento viene scartato con un warning (protezione da
   back-pressure).

5. **Detection** — `main` legge il canale e chiama `detector.Check(event)`. Il
   detector **ignora gli eventi host** (`event.Container == nil`) e altrimenti esegue
   le regole **in ordine**; vince la **prima** regola che matcha. Il detector poi
   marca l'alert con ID/nome container, immagine, PID, nome processo, nome syscall e
   timestamp.

6. **Alerting** — `alerter.Send(alert)`:
   - Scarta l'alert se la sua severità è sotto `CS_ALERT_MIN_SEVERITY`.
   - Applica il **rate limiting per container a finestra scorrevole**
     (`CS_ALERT_MAX_RATE` eventi ogni `CS_ALERT_RATE_WINDOW` secondi).
   - Marca `ServerName` e (se mancante) `Timestamp`.
   - Smista verso ogni destinazione abilitata: file di log JSON (sincrono) e webhook +
     Slack (ciascuno in una propria goroutine).

7. **Statistiche e shutdown** — `main` conta `processed`/`alerted`, loggando le
   statistiche ogni 10.000 eventi. Su SIGINT/SIGTERM ferma il collector, chiude
   l'alerter e logga i conteggi finali.

## Il contratto binario dell'evento

L'invariante più importante del codebase: la `struct event` C in `tracer.c` e il
`RawEvent` Go in `collector.go` **devono avere layout di memoria identico**. La
decodifica è una `binary.Read` grezza con `binary.LittleEndian`, quindi contano
ordine dei campi, dimensioni e padding.

| Campo C (`tracer.c`) | Campo Go (`RawEvent`) | Dim. | Note |
|---|---|---|---|
| `__u32 pid` | `PID uint32` | 4 | 32 bit alti di `pid_tgid` |
| `__u32 ppid` | `PPID uint32` | 4 | 32 bit bassi di `pid_tgid` (vedi nota) |
| `__u32 uid` | `UID uint32` | 4 | |
| `__u8 event_type` | `EventType uint8` | 1 | costante `EVENT_*` |
| _(padding)_ | `_ [3]byte` | 3 | allinea il campo successivo |
| `char comm[16]` | `Comm [16]byte` | 16 | nome processo |
| `char filename[128]` | `Filename [128]byte` | 128 | percorso execve/open |
| `__u16 dport` | `DPort uint16` | 2 | network byte order |
| _(padding)_ | `_ [2]byte` | 2 | allinea il campo successivo |
| `__u32 daddr` | `DAddr uint32` | 4 | IPv4, little-endian su x86 |
| `__u64 timestamp_ns` | `TimestampNS uint64` | 8 | `bpf_ktime_get_ns()` |

> **Nota su PID/PPID:** la funzione kernel `bpf_get_current_pid_tgid()` restituisce
> `tgid<<32 | pid`. Il codice mappa la word alta su `PID` e quella bassa su `PPID`. La
> word bassa è in realtà il *thread id* del kernel, non il PID del padre, quindi
> "PPID" è una piccola imprecisione nell'implementazione attuale.

Le costanti del tipo evento sono duplicate in due punti e devono restare sincronizzate:
`EVENT_EXECVE/OPEN/CONNECT/CLONE` (1–4) in `tracer.c` e `EventExecve/Open/Connect/
Clone` in `collector.go`.

## Modello di concorrenza

- **Una goroutine lettore** (`readLoop`) alimenta il canale bufferizzato degli eventi.
- **La goroutine principale** consuma il canale ed esegue la detection in modo sincrono.
- **Gli invii webhook e Slack** girano in goroutine effimere dedicate, così un endpoint
  lento non blocca mai l'event loop.
- **Il mapper** ha una **goroutine di eviction** interna (`evictLoop`, tick ogni 30 s)
  che ripulisce le voci di cache più vecchie del TTL (5 minuti, impostato in `main.go`).
  La cache è protetta da un `sync.RWMutex`; lo stato del rate-limit da un proprio mutex.

## Ambiente di runtime

Il demone necessita visibilità sull'host, concessa in `docker-compose.yml`:

- `network_mode: host` — per osservare tutta l'attività di rete dei container.
- `pid: "host"` — così i PID host dell'eBPF si risolvono via `/proc/<pid>/cgroup`.
- Mount (minimi): `/var/run/docker.sock` (previsto per i metadati) e un volume nominato
  per il log degli alert. Nessun mount BTF / bpffs / `/proc` necessario (niente CO-RE;
  `/proc` arriva da `pid:host`).
- Capability: gira come root con `cap_drop: ALL` + `cap_add` `SYS_ADMIN` (caricare
  eBPF), `SYS_PTRACE` (leggere `/proc/<pid>`), `NET_ADMIN` (tracepoint di rete) — un set
  ristretto, non `privileged: true` completo. (L'eBPF richiede capability *effettive*,
  che un utente non-root non manterrebbe.)
