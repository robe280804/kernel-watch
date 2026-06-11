package collector

// bpf2go compiles ebpf/tracer.c and generates the Go scaffolding
// (tracerObjects, loadTracerObjects, the program/map handles) directly into
// THIS package, so collector.go can reference the unexported tracer* symbols.
//
// Run `go generate ./...` (requires clang + libbpf-dev). tracer.c is
// self-contained — no vmlinux.h and no host BTF are needed.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tracer ../../ebpf/tracer.c
