# Development guide

## Layout

```
main.go                       entry point + event loop
ebpf/tracer.c                 kernel-space eBPF program (//go:build ignore)
internal/config/config.go     env → Config
internal/container/mapper.go  PID → container Info
internal/collector/collector.go  eBPF load + ring buffer + parse/enrich
internal/detector/detector.go    detection rules
internal/alerter/alerter.go      alert dispatch + rate limit
```

## eBPF code generation

`internal/collector/gen.go` carries the directive (kept in the `collector` package
so the generated symbols land where they are used):

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tracer ../../ebpf/tracer.c
```

Running `go generate ./...`:

1. Compiles `ebpf/tracer.c` to BPF bytecode with `clang` (needs `libbpf-dev` for the
   `<bpf/*.h>` headers and `linux-libc-dev` for `<linux/bpf.h>`). `tracer.c` is
   self-contained — no `vmlinux.h` / host BTF required.
2. Emits generated Go files (`tracer_bpfel.go` / `tracer_bpfeb.go`) **into
   `internal/collector/`** that embed the bytecode and declare `tracerObjects`,
   `loadTracerObjects`, and the program/map handles (`TraceExecve`, `TraceOpenat`,
   `TraceConnect`, `TraceClone`, `Events`).

These generated files are **required to compile** the `collector` package and are
**not committed** — you must run `go generate` (with clang installed) before
`go build`. The Dockerfile does this automatically.

No `vmlinux.h` and no pre-existing `go.sum` are needed (`go mod download` generates
`go.sum` in-build).

## Local build

```bash
sudo apt install -y clang llvm libbpf-dev linux-libc-dev
go generate ./...
go build -o kernelwatch .
sudo ./kernelwatch
```

## Adding a new detection rule

1. Write a rule in `internal/detector/detector.go`:

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

2. Register it in `New()`'s `d.rules = []Rule{...}` slice. Order matters
   (first match wins) — put more specific/important rules earlier.

3. The detector auto-stamps container/process/syscall/timestamp; your rule only
   sets severity, reason, MITRE fields and `Details`.

## Adding a new syscall hook

1. In `ebpf/tracer.c`: add an `EVENT_*` constant, a `SEC("tracepoint/syscalls/
   sys_enter_<name>")` program that `fill_common`s and reads the args you need,
   then `bpf_ringbuf_submit`.
2. If you add fields to `struct event`, mirror them **exactly** in
   `collector.RawEvent` (order, sizes, padding) and update `parseEvent`.
3. Add the matching `EventXxx` constant in `collector.go` and a `TypeName()` case.
4. Attach the tracepoint in `Collector.Start()`'s `tps` slice using the generated
   `c.objs.Trace<Name>` handle.
5. `go generate ./...` to regenerate, then build.

## Things to be careful with

- **Layout sync** between `struct event` and `RawEvent` — the decode is raw
  little-endian `binary.Read`; a mismatch silently corrupts every field.
- **The `strings` shim** in `alerter.go` shadows the standard library with a
  hand-rolled `ToUpper`. If you need real string helpers there, import `"strings"`
  and remove the shim (and `ToLower` etc. used elsewhere already import the real
  package in their own files).
- **Ring-buffer size** from config is currently not applied at load — wire it into
  the eBPF map options if you need a non-default size.

## Suggested next steps for contributors

See [roadmap.md](roadmap.md). The highest-leverage gaps are: a `go.sum` + a few
unit tests (rules and `extractContainerID` are pure and easy to test), the REST
API, and TimescaleDB persistence with migrations.
