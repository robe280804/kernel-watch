//go:build ignore
// This file is compiled by `go generate` via cilium/ebpf's bpf2go tool.
// It runs in kernel space and sends events to userspace via a ring buffer.
//
// Self-contained by design: it pulls only the stable UAPI header <linux/bpf.h>
// (BPF_MAP_TYPE_RINGBUF, __u* types) and libbpf's <bpf/bpf_helpers.h> (SEC,
// helpers, the __uint map macros). The one kernel-internal type we need,
// struct trace_event_raw_sys_enter, is declared here with its stable ABI layout
// instead of being pulled from a host-generated vmlinux.h.
//
// Why no vmlinux.h / CO-RE: we only read syscall tracepoint arguments by their
// fixed ABI offset (8 bytes of common trace_entry, then the syscall id, then
// args[6]). That layout is stable across kernels, so the program loads on any
// kernel 5.15+ WITHOUT being recompiled against each kernel's BTF. This keeps
// the build reproducible on any Linux host — no bpftool, no committed headers.
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

// ── Event types ───────────────────────────────────────────────────────────────
#define EVENT_EXECVE   1   // process execution
#define EVENT_OPEN     2   // file opening
#define EVENT_CONNECT  3   // exit connection
#define EVENT_CLONE    4   // new process/thread

// ── Syscall tracepoint context (stable ABI layout) ───────────────────────────
// Mirrors the kernel's struct trace_event_raw_sys_enter:
//   struct trace_entry ent;   // 8 bytes of common header
//   long              id;     // syscall number
//   unsigned long     args[6];
struct trace_event_raw_sys_enter {
    __u64         _common;     // trace_entry (type/flags/preempt/pid) = 8 bytes
    long          id;          // syscall number
    unsigned long args[6];     // syscall arguments
};

// ── Event structure sent to userspace ────────────────────────────────────────
// Keep this struct in sync with the Go struct in collector.go
struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  event_type;       // EVENT_* constants above
    char  comm[16];         // process name (from task_struct)
    char  filename[128];    // for execve/open: file path
    __u16 dport;            // for connect: destination port (network byte order)
    __u32 daddr;            // for connect: destination IPv4 address
    __u64 timestamp_ns;     // bpf_ktime_get_ns()
};

// ── Ring buffer map (kernel → userspace) ─────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB — overridden at load time by Go
} events SEC(".maps");

// ── Helper: populate common fields ───────────────────────────────────────────
static __always_inline void fill_common(struct event *e, __u8 type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid        = pid_tgid >> 32;
    e->ppid       = pid_tgid & 0xFFFFFFFF;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = type;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ── execve — new process execution ───────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_EXECVE);

    // Read the filename argument (first arg to execve)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── openat — file access ──────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_OPEN);

    // Read the path argument (second arg to openat)
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // Only emit events for interesting paths to reduce noise
    // (full filtering happens in userspace — here we just record)
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── connect — outbound network connections ────────────────────────────────────
// Minimal IPv4 sockaddr view, defined locally (we don't pull netinet headers).
struct sa_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_CONNECT);

    // Read the sockaddr struct (second arg to connect)
    struct sa_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);

    // Only track IPv4 (AF_INET = 2)
    if (sa.sin_family == 2) {
        e->dport = sa.sin_port;
        e->daddr = sa.sin_addr;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── clone — process/thread creation ──────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_CLONE);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
