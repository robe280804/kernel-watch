# KernelWatch — Documentation (English)

KernelWatch is an **eBPF-based Host Intrusion Detection System (HIDS)** for
Docker containers. It hooks Linux syscalls in **kernel space** and detects
suspicious behaviour inside running containers — **without installing any agent
inside the containers themselves**.

Because the monitoring lives in the kernel, an attacker who compromises a
container cannot disable it from within.

> The Go module is named `kernelwatch`. (An early build logged the startup
> line as "KernelWatch" — now corrected to "KernelWatch starting".)

## Documentation index

| Document | What you'll find |
|---|---|
| [overview.md](overview.md) | What the project is, core concepts (eBPF, HIDS, ring buffer), maturity. |
| [architecture.md](architecture.md) | How the components fit together, the end-to-end data flow, the binary event layout. |
| [components.md](components.md) | File-by-file reference of every source file, with key functions and structs. |
| [configuration.md](configuration.md) | Every `KW_*` environment variable, defaults, and validation rules. |
| [detection-rules.md](detection-rules.md) | The 6 detection rules, what triggers them, severities and MITRE ATT&CK mapping. |
| [deployment.md](deployment.md) | Docker / Docker Compose deployment, required capabilities, build from source. |
| [dashboard.md](dashboard.md) | The optional web dashboard: enabling it, accessing it (SSH tunnel / reverse proxy), and what you can do (stats, alerts, suppressions). |
| [development.md](development.md) | Local build, eBPF code generation, how to add a new rule or syscall hook. |
| [roadmap.md](roadmap.md) | Roadmap, known limitations, stubs and bugs to be aware of. |

## At a glance

- **Language:** Go 1.22 + eBPF (C), compiled via `bpf2go`.
- **Only dependency:** `github.com/cilium/ebpf v0.15.0`.
- **Syscalls hooked:** `execve`, `openat`, `connect`, `clone`.
- **Detections:** shell in container, privilege-escalation tools, sensitive-file
  access, network recon tools, package managers, credential-file access.
- **Alert destinations:** JSON log file, webhook (HMAC-SHA256 signed), Slack, stdout.
- **Requirements:** Linux kernel 5.15+, root / eBPF capabilities. Self-contained build (no host BTF).

## Quick start

```bash
cp .env.example .env          # set at least KW_SERVER_NAME and KW_API_TOKEN
docker compose up -d --build
docker compose logs -f kernelwatch
```

See [deployment.md](deployment.md) for full details.
