# Detection rules

The detector (`internal/detector/`) is **context-aware**: it judges each
**container** event (host events are ignored) not only by the binary involved
but by **who launched it (process ancestry)** and **with what arguments (argv)**.
This is what separates real attacks from routine operations — the same `sh` or
`curl` is benign from `cron` and a likely web-shell from `nginx`.

Rules are declarative units (`internal/detector/rules.go`) built from reusable
**lists** (`lists.go`). The engine (`detector.go`) runs **all** rules, applies
operator **exceptions**, and de-duplicates by `(rule, container, pid)` within a
short window. Each alert carries a rule id, severity, MITRE ATT&CK
technique/tactic, tags, the parent/ancestry, and the command line.

## Enrichment behind the rules

The collector traces 8 syscall tracepoints (execve, openat, connect, clone,
ptrace, init_module, finit_module, bpf). For monitored container `execve`
(and `ptrace`/module/`bpf`) events it resolves, in userspace (via `/proc`, like
the existing cgroup lookup — no extra eBPF):

- **Ancestry** — the chain of parent process names (`/proc/<pid>/stat` →
  `/proc/<ppid>/comm`), up to `KW_ANCESTRY_DEPTH` (default 5), immediate parent
  first.
- **Command line** — `/proc/<pid>/cmdline` (the executed argv).
- **Container name/image** — resolved from the Docker socket, so alerts and
  `KW_CONTAINER_*` filters use real names instead of short IDs.

## Lineage classification

Each ancestry chain is classified using two lists (overridable via config):

- **Trusted** (`KW_TRUSTED_PARENTS` + built-ins: `init`, `systemd`, `cron`,
  `containerd-shim`, `runc`, `tini`, `dumb-init`, `s6-*`, `supervisord`, …) —
  benign supervisors/schedulers/entrypoints.
- **Network-facing** (`KW_NETWORK_PARENTS` + built-ins: `nginx`, `apache2`,
  `httpd`, `php-fpm`, `php`, `node`, `python`, `java`, `ruby`, `puma`,
  `gunicorn`, `mysqld`, `postgres`, `redis-server`, …) — internet-exposed
  service runtimes. **Network-facing wins** when both appear in a chain.

---

## Rules

| Rule id | Trigger | Lineage behaviour | Severity | MITRE |
|---------|---------|-------------------|----------|-------|
| `kernel_module_load` | `init_module`/`finit_module` from a container | n/a | **Critical** | T1547.006 Persistence |
| `bpf_prog_load` | `bpf(BPF_PROG_LOAD)` from a container | n/a | High | T1562.001 Defense Evasion |
| `process_injection` | `ptrace` with POKETEXT/POKEDATA/POKEUSR/SETREGS/ATTACH/SEIZE | n/a | High | T1055.008 Privilege Escalation |
| `persistence` | **write-mode** open of cron/systemd/`ld.so.preload`/`authorized_keys`/`sudoers.d`/profile paths | n/a | High (Critical for `ld.so.preload`) | T1543 Persistence |
| `reverse_shell` | `execve` cmdline matches a reverse-shell signature (`/dev/tcp/`, `/dev/udp/`, `nc -e`, `ncat -e`, `pty.spawn`, `socket.socket`, or `curl/wget … \| sh`) | always fires (never benign) | **Critical** | T1059 Execution |
| `shell_in_container` | `execve` of `sh`/`bash`/`zsh`/`fish`/`dash`/`ash`/`ksh`/`tcsh` | network → **Critical** (RCE/web-shell); trusted → **suppressed**; unknown → High | High→Critical | T1059 Execution |
| `privilege_escalation` | `execve` of `sudo`/`su`/`nsenter`/`unshare`/`chroot`/`capsh`/`setuid`/`newgrp` | network → **Critical**; trusted → suppressed; unknown → High | High→Critical | T1548 Privilege Escalation |
| `network_tool` | `execve` of `nmap`/`masscan`/`nc`/`ncat`/`netcat`/`socat`/`curl`/`wget`/`tcpdump`/… | network → **High**; trusted → **suppressed**; unknown → Medium (High for `nmap`/`masscan`) | Medium→High | T1046 Discovery |
| `container_drift` | `execve` of a binary under `/tmp`, `/dev/shm`, `/var/tmp`, `/run` | n/a | High | T1036 Defense Evasion |
| `package_manager` | `execve` of `apt`/`apt-get`/`dpkg`/`yum`/`dnf`/`apk`/`pip`/`npm`/… | network → **High**; trusted → suppressed; unknown → Medium | Medium→High | T1072 Execution |
| `sensitive_file` | `openat` path-prefix of `/etc/shadow`, `/root/.ssh`, `/var/run/docker.sock`, … | n/a | Medium (Critical for docker.sock → T1611) | T1005 Collection |
| `credential_file` | `openat` path-prefix of `/.env`, `/.aws/credentials`, `/run/secrets`, `/.kube/config`, … | n/a | High | T1552 Credential Access |

The decisive change: `shell_in_container`, `network_tool`, `package_manager`,
and `privilege_escalation` are **suppressed** for trusted lineage (killing the
scheduler/healthcheck/autoheal noise) and **escalated** for network-facing
lineage (catching real RCE/web-shells).

---

## Operational modes & tuning

- **`KW_MODE`** — `alert` (default) dispatches; `monitor` is a dry-run that
  evaluates and logs but never calls webhook/Slack. Use `monitor` for a safe
  rollout/tuning period on a new host.
- **`KW_DETECTION_EXCEPTIONS`** — comma-separated substrings; an alert is
  suppressed if any appears in the container name, image, command line, or
  ancestry. The escape hatch for residual false positives.
- **`KW_ALERT_MIN_SEVERITY`** still gates delivery (see
  [configuration.md](configuration.md)).

## Known limitations

- **argv/ancestry race** — an ultra-short-lived process may exit before `/proc`
  is read; rules then fall back to the binary path only.
- **List-based binary matching** — a renamed shell still evades the binary
  lists, but `container_drift` and `reverse_shell` (argv-based) provide
  independent coverage.
- **`container_drift`** currently flags writable-path execution only;
  argv[0] masquerade and image-manifest comparison are deferred (would
  false-positive on login shells / busybox).

## Adding a rule

Add a `Rule` value in `internal/detector/rules.go` (id, severity, MITRE, tags,
and a `Match` func returning a `*hit` or `nil`) and register it in
`defaultRules()`. Add a table case to `detector_test.go`. See
[development.md](development.md).

## Roadmap

A **behavioural-anomaly engine** (STIDE / n-gram syscall-sequence baselining per
workload) is planned to complement these signatures and catch unknown attacks —
see [roadmap.md](roadmap.md).
