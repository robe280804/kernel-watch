# Guida allo sviluppo

## Struttura

```
main.go                       entry point + event loop
ebpf/tracer.c                 programma eBPF nello spazio kernel (//go:build ignore)
internal/config/config.go     env → Config
internal/container/mapper.go  PID → Info container
internal/collector/collector.go  load eBPF + ring buffer + parse/arricchimento
internal/detector/detector.go    regole di detection
internal/alerter/alerter.go      smistamento alert + rate limit
```

## Generazione del codice eBPF

`internal/collector/gen.go` contiene la direttiva (tenuta nel package `collector`
così i simboli generati finiscono dove vengono usati):

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tracer ../../ebpf/tracer.c
```

Eseguendo `go generate ./...`:

1. Compila `ebpf/tracer.c` in bytecode BPF con `clang` (serve `libbpf-dev` per gli
   header `<bpf/*.h>` e `linux-libc-dev` per `<linux/bpf.h>`). `tracer.c` è
   self-contained — nessun `vmlinux.h` / BTF host richiesto.
2. Emette file Go generati (`tracer_bpfel.go` / `tracer_bpfeb.go`) **dentro
   `internal/collector/`** che incorporano il bytecode e dichiarano `tracerObjects`,
   `loadTracerObjects` e gli handle dei programmi/mappe (`TraceExecve`, `TraceOpenat`,
   `TraceConnect`, `TraceClone`, `Events`).

Questi file generati sono **necessari per compilare** il package `collector` e **non
sono committati** — devi eseguire `go generate` (con clang installato) prima di
`go build`. Il Dockerfile lo fa automaticamente.

Non servono né `vmlinux.h` né un `go.sum` preesistente (`go mod download` genera
`go.sum` in build).

## Build locale

```bash
sudo apt install -y clang llvm libbpf-dev linux-libc-dev
go generate ./...
go build -o containersentry .
sudo ./containersentry
```

## Aggiungere una nuova regola di detection

1. Scrivi una regola in `internal/detector/detector.go`:

   ```go
   func ruleCryptominerExec(e collector.Event) *alerter.Alert {
       if e.Type != collector.EventExecve {
           return nil
       }
       miners := []string{"xmrig", "minerd", "cpuminer"}
       comm := strings.ToLower(e.ProcessName)
       for _, m := range miners {
           if comm == m {
               return &alerter.Alert{
                   Severity:    alerter.SeverityCritical,
                   Reason:      "cryptominer executed inside container",
                   MITRETTP:    "T1496",
                   MITRETactic: "Impact",
                   Details:     map[string]any{"binary": e.ProcessName},
               }
           }
       }
       return nil
   }
   ```

2. Registrala nello slice `d.rules = []Rule{...}` in `New()`. L'ordine conta (vince la
   prima che matcha) — metti prima le regole più specifiche/importanti.

3. Il detector marca automaticamente container/processo/syscall/timestamp; la tua
   regola imposta solo severità, reason, campi MITRE e `Details`.

## Aggiungere un nuovo hook syscall

1. In `ebpf/tracer.c`: aggiungi una costante `EVENT_*`, un programma `SEC("tracepoint/
   syscalls/sys_enter_<nome>")` che faccia `fill_common` e legga gli argomenti che ti
   servono, poi `bpf_ringbuf_submit`.
2. Se aggiungi campi a `struct event`, rispecchiali **esattamente** in
   `collector.RawEvent` (ordine, dimensioni, padding) e aggiorna `parseEvent`.
3. Aggiungi la costante `EventXxx` corrispondente in `collector.go` e un case in
   `TypeName()`.
4. Aggancia il tracepoint nello slice `tps` di `Collector.Start()` usando l'handle
   generato `c.objs.Trace<Nome>`.
5. `go generate ./...` per rigenerare, poi build.

## Cose a cui fare attenzione

- **Sincronizzazione del layout** tra `struct event` e `RawEvent` — la decodifica è una
  `binary.Read` grezza little-endian; una discrepanza corrompe silenziosamente ogni
  campo.
- **Lo shim `strings`** in `alerter.go` oscura la libreria standard con un `ToUpper`
  fatto a mano. Se ti servono veri helper di stringa lì, importa `"strings"` e rimuovi
  lo shim (`ToLower` ecc. usati altrove importano già il vero package nei loro file).
- **Dimensione del ring buffer** dalla config attualmente non applicata al load —
  collegala alle opzioni della mappa eBPF se ti serve una dimensione non di default.

## Prossimi passi suggeriti per i contributor

Vedi [roadmap.md](roadmap.md). I gap a maggior leva sono: un `go.sum` + qualche test
unitario (le regole ed `extractContainerID` sono pure e facili da testare), la REST API
e la persistenza TimescaleDB con le migration.
