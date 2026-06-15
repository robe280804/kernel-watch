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

Rules are **data**, not Go code. You almost never need to recompile — add a rule
in YAML and load it via `KW_RULES_FILE` / `KW_RULES_DIR` (see
[detection-rules.md](detection-rules.md#rule-engine-yaml-falco-style)).

1. Write the rule (a condition over the field set, optionally a `lineage:`
   matrix), e.g. a cryptominer detector:

   ```yaml
   lists:
     miners: [xmrig, minerd, cpuminer]
   rules:
     - id: cryptominer_exec
       scope: all
       tactic: Impact
       technique: T1496
       tags: [mining]
       condition: "evt.type = execve and in_list(proc.exe_base, $miners)"
       severity: critical
       reason: "cryptominer executed"
       details: { binary: proc.exe_base }
   ```

2. Validate it without root or eBPF: `KW_RULES_FILE=my.yaml kernelwatch --validate`.

3. To change a built-in rule, override it by id (`override: true`), extend it
   (`append: true`), or disable it (`enabled: false`) in your overlay file.

The detector auto-stamps scope/container/process/syscall/timestamp; your rule
only sets the condition, severity, reason, MITRE fields and `details`.

To change the **embedded default** ruleset itself, edit
`internal/ruleengine/default.yaml` (covered by `go test ./internal/ruleengine/...`
and the detector parity test). The DSL/engine lives in `internal/ruleengine/`.

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
