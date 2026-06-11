# Panoramica

## Cos'è KernelWatch?

KernelWatch è un **sistema di rilevamento intrusioni a livello host (HIDS)**
specializzato per **container Docker**. Osserva le syscall che i processi dei
container effettuano e genera alert quando rileva comportamenti che un container di
produzione sano non dovrebbe mai avere — ad esempio l'avvio di una shell, la lettura
di `/etc/shadow`, l'accesso al socket Docker o l'esecuzione di `nmap`.

La caratteristica distintiva è **dove** avviene l'osservazione: nel **kernel Linux**,
usando **eBPF**. L'applicazione non inietta nulla nei container monitorati. Un solo
demone sull'host vede tutto.

## Perché eBPF?

eBPF permette di eseguire piccoli programmi verificati dentro il kernel, attivati da
eventi del kernel (qui, i punti di ingresso delle syscall). Rispetto alle alternative:

- **vs. agente nel container:** niente da installare per ogni container; un
  attaccante che possiede il container non può manomettere il monitor (gira nel
  kernel).
- **vs. modulo kernel:** nessuna ricompilazione, nessun rischio di panico del
  kernel; il verificatore eBPF garantisce che il programma sia sicuro da eseguire.
- **vs. polling di `/proc`:** gli eventi vengono spinti nell'istante in cui la
  syscall scatta, senza buchi di campionamento.

KernelWatch usa i **tracepoint** (punti di strumentazione stabili del kernel) su
quattro syscall e fa fluire gli eventi verso lo spazio utente tramite un **ring
buffer** (`BPF_MAP_TYPE_RINGBUF`), un canale kernel→userspace ad alto throughput e a
basso lock.

È costruito con **CO-RE** (Compile Once – Run Everywhere) tramite BTF, quindi lo
stesso programma compilato gira su versioni di kernel diverse senza ricompilare
contro gli header di ciascun kernel.

## Concetti chiave

| Termine | Significato in questo progetto |
|---|---|
| **Programma eBPF** | Il codice C in `ebpf/tracer.c`, compilato in bytecode e caricato nel kernel. |
| **Tracepoint** | Un hook stabile del kernel. Ci agganciamo a `sys_enter_execve/openat/connect/clone`. |
| **Ring buffer** | Il canale kernel→userspace che trasporta gli eventi grezzi (16 MB di default). |
| **Collector** | Il codice Go che carica il programma eBPF, legge il ring buffer e analizza gli eventi. |
| **Mapper** | Risolve un PID nel suo container Docker analizzando `/proc/<pid>/cgroup`. |
| **Detector** | Un insieme di regole che ispezionano ogni evento arricchito e decidono se è un alert. |
| **Alerter** | Smista gli alert verso file di log / webhook / Slack con rate limiting. |
| **CO-RE / BTF** | Il meccanismo che rende il programma eBPF portabile tra kernel diversi. |

## Quadro end-to-end

```
syscall in un container
        │  (kernel)
        ▼
ebpf/tracer.c  ──submit──►  ring buffer  ──►  collector (legge e analizza)
                                                   │
                                                   ▼
                                         mapper: PID → container?
                                                   │ (scarta processi host)
                                                   ▼
                                         detector: esegue 6 regole
                                                   │ (vince la prima che matcha)
                                                   ▼
                                         alerter: filtro severità +
                                         rate limit → log / webhook / Slack
```

Dettaglio completo in [architecture.md](architecture.md).

## Maturità del progetto

La **pipeline core è completa e coerente**: cattura kernel → parsing →
arricchimento container → detection a regole → alerting multi-destinazione, il tutto
collegato in `main.go` con shutdown pulito.

**Cosa è solido oggi**

- Collector eBPF con 4 hook syscall e streaming via ring buffer.
- 6 regole di detection mappate su MITRE.
- Alerting multi-destinazione (file, webhook firmato HMAC, Slack, stdout).
- Rate limiting per container a finestra scorrevole.
- Risoluzione container via cgroup (v1 e v2) con cache a TTL.
- Dockerfile multi-stage e un `docker-compose.yml` di forma production.

**Cosa è incompleto o stub** (lista completa in [roadmap.md](roadmap.md))

- REST API / dashboard: una porta è configurata (`KW_API_PORT`) ma **non esistono
  handler HTTP**.
- Persistenza su database: TimescaleDB è definito in Compose, ma **non c'è schema né
  logica di insert**, e la directory `./migrations` non esiste ancora.
- `dockerInspect()` nel mapper è uno **stub** — nome/immagine del container non sono
  arricchiti dalla Docker API; come nome si usa lo short ID del container.
- La dimensione del ring buffer eBPF configurata **non viene effettivamente
  applicata** al momento del load.
- Nessun test, nessun `go.sum` committato, non è un repository git.
- Alcune particolarità del codice documentate in [components.md](components.md) e
  [roadmap.md](roadmap.md).
