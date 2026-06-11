# Roadmap, limitazioni & problemi noti

## Roadmap (dal README del progetto)

- [ ] Profiler statico — analisi pre-deploy delle immagini con `syft`.
- [ ] Baseline comportamentale per container — anomaly detection con autoencoder ML.
- [ ] REST API + dashboard WebSocket.
- [ ] Integrazione TimescaleDB per lo storico degli eventi.
- [ ] Supporto Kubernetes DaemonSet.
- [ ] Arricchimento MITRE ATT&CK per tutte le regole.

## Correzioni di stabilizzazione già applicate

Bloccavano una build/esecuzione funzionante e sono state corrette nel repo:

- **Package target di bpf2go**: la direttiva `//go:generate` è stata spostata da
  `main.go` a `internal/collector/gen.go`, così i generati `tracerObjects`/
  `loadTracerObjects` finiscono nel package `collector` (dove servono). Prima
  sarebbero stati generati in `package main` e `collector` non avrebbe compilato.
- **Build eBPF riproducibile**: `tracer.c` è self-contained — dichiara l'unica struct
  kernel che gli serve (ABI dei tracepoint stabile), quindi **niente `vmlinux.h` né
  BTF host**. Il Dockerfile installa `libbpf-dev` + `linux-libc-dev` e rimuove il
  `linux-headers-generic` non valido su Debian. Risultato: `git clone` +
  `docker compose up --build` funziona su qualsiasi host Linux.
- **`go.sum` auto-generato**: il Dockerfile lo copia in modo opzionale (`go.sum*`) e
  `go mod download` lo genera in build — niente `go mod tidy` manuale.
- **L'eBPF si carica davvero**: il container gira come **root** con `cap_drop: ALL` +
  `cap_add` mirato. Un utente non-root non manterrebbe le capability effettive
  concesse da `cap_add`, quindi il load eBPF sarebbe fallito silenziosamente.
- **Risoluzione PID**: `docker-compose.yml` imposta `pid: "host"`, così i PID host
  dell'eBPF si risolvono via `/proc/<pid>/cgroup`. Senza, il detector vedeva ogni
  evento come processo host e generava **zero** alert. (Mount BTF/bpffs/`/proc` inutili
  rimossi.)
- **Detection execve**: le regole matchano ora sul basename del binario eseguito
  (`e.Filename`) invece che su `comm`, che a `sys_enter_execve` contiene ancora il
  nome del chiamante — così le regole shell/tool/package-manager scattano davvero.
- **Pulizia**: rimosso lo shim `strings` in `alerter.go` (vero `import "strings"`),
  rinominato il log di avvio in "ContainerSentry starting", aggiunto
  `migrations/.gitkeep`, rimossa una directory spuria da brace-expansion.

## Ancora incompleto / stub

| Area | Stato | Dettaglio |
|---|---|---|
| REST API | Non implementata | `CS_API_PORT`/`CS_API_TOKEN` esistono; nessun server o handler HTTP. |
| Dashboard (WebSocket) | Non implementata | Solo roadmap. |
| Persistenza DB | Non implementata | `Config.DSN()` pronto; nessuna connessione, schema o insert. |
| Arricchimento Docker | Stub | `dockerInspect()` restituisce sempre "not implemented"; nome = short ID, immagine = vuota. |
| Dimensionamento ring buffer | Inattivo | `CS_EBPF_RINGBUF_SIZE` è caricata ma non applicata al load eBPF. |
| Test | Nessuno | Nessun file `_test.go`. |

## Quirk rimasti da sistemare

- **"PPID" è il thread id** (`tracer.c` / `collector.go`): la word bassa di
  `bpf_get_current_pid_tgid()` è il thread id del kernel, non il PID del padre.
  Rinominalo o recupera il vero padre via `task_struct->real_parent` se ti serve il
  vero PPID.
- **Il filtraggio per nome dipende dall'arricchimento**: `IsMonitored` matcha sui nomi
  dei container, ma finché `dockerInspect` non funziona il "nome" è lo short ID di 12
  caratteri, quindi whitelist/blacklist per nome amichevole non corrisponderanno.

## Una previsione realistica

La parte difficile e differenziante — la cattura eBPF a livello kernel con una pipeline
pulita collector→detector→alerter — è **fatta e coerente**. Ciò che resta è per lo più
l'idraulica "poco glamour ma necessaria":

**Breve termine (completare l'MVP)**
1. (Fatto) Build riproducibile + load eBPF funzionante — vedi "Correzioni di
   stabilizzazione" sopra.
2. Implementare l'arricchimento via Docker API (`dockerInspect` / collegare
   `ParseDockerList`) così che gli alert portino nomi e immagini reali dei container e
   il filtraggio per nome funzioni.
3. REST API + persistenza (schema TimescaleDB, insert, endpoint di query autenticati
   con `CS_API_TOKEN`).

**Medio termine (robustezza)**
4. Test unitari per la logica pura (regole, `extractContainerID`, rate limiter) e le
   piccole correzioni delle particolarità sopra; aggiungere CI.
5. Una dashboard web sopra l'API (feed live + storico).
6. Baseline comportamentale per container a complemento delle regole statiche.

**Lungo termine (scala)**
7. Kubernetes DaemonSet — il salto da Docker su host singolo alla copertura su
   tutto il cluster.
8. Arricchimento MITRE più profondo e correlazione degli eventi (alert singoli →
   catene di attacco).

Se il progetto supera l'idraulica di breve termine, ha un percorso credibile per
diventare un'alternativa open e leggera nello spazio occupato da strumenti come
Falco/Sysdig e Aqua — l'architettura e la postura di sicurezza (spazio kernel, minimo
privilegio, non-root, taggatura MITRE) sono già solide.
