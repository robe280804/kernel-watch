# Detection rules

The detector (`internal/detector/`) is **context-aware**: it judges each event
not only by the binary involved but by **who launched it (process ancestry)**
and **with what arguments (argv)**. This is what separates real attacks from
routine operations — the same `sh` or `curl` is benign from `cron` and a likely
web-shell from `nginx`.

By default the detector evaluates **container** events only. Set
`KW_MONITOR_HOST=true` to additionally monitor the **Docker host itself**
(processes that are not in any container) — see
[Host (whole-server) monitoring](#host-whole-server-monitoring) below. Every
alert carries a `scope` of `container` or `host`.

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
  `httpd`, `php-fpm`, `node`, `java`, `puma`, `unicorn`, `gunicorn`, `uwsgi`,
  `mysqld`, `postgres`, `redis-server`, …) — internet-exposed **server daemons**.
  Bare language runtimes (`php`, `python`, `ruby`) are deliberately excluded: a
  web RCE goes through the daemon (`php-fpm`), while the bare interpreter is the
  scheduler/queue/CLI (`php artisan`) and would false-positive.
  **Network-facing wins** when both appear in a chain.

---

## Rule engine (YAML, Falco-style)

Detection rules are **data, not code**. A built-in ruleset is embedded in the
binary (`internal/ruleengine/default.yaml`); operators extend, override, or
disable rules **without recompiling** by pointing `KW_RULES_FILE` (one file) or
`KW_RULES_DIR` (a directory of `*.yaml`, lexical order) at their own YAML, which
**merges on top** of the defaults. The table below is the embedded default set.

A rule is a condition over a small field set, an optional **lineage matrix**, and
metadata:

```yaml
lists:
  shells: [sh, bash, zsh, dash, ash, ksh]
macros:
  spawns_shell: "evt.type = execve and in_list(proc.exe_base, $shells)"
rules:
  - id: shell_in_container
    scope: container            # container | host | all
    tactic: Execution
    technique: T1059
    tags: [container, shell]
    condition: spawns_shell
    lineage:                    # first matching arm wins; action:suppress => no alert
      - when: network
        severity: critical
        reason: "shell spawned by a network-facing service (RCE/web-shell)"
        details: { shell: proc.exe_base, spawned_by: lineage.network_parent }
      - when: trusted
        action: suppress
      - when: [unknown, interactive]
        severity: high
        reason: "shell execution inside container"
```

**Condition DSL** — `and` / `or` / `not`, comparisons (`=`, `!=`, `&`
bitmask-nonzero, `in`, `contains`, `startswith`), `$list` references, `[..]`
literals, and helpers: `in_list`, `chain_in_list`, `has_prefix`, `contains_any`,
`is_trusted_writer`, `is_docker_client`, `reverse_shell`.

**Fields** — `evt.type`, `evt.is_open_write`, `evt.is_open_trunc`, `proc.name`,
`proc.exe_base`, `proc.exe_path`, `proc.cmdline`, `proc.cmdline_lc`, `fd.name`,
`fd.directory`, `scope`, `lineage`, `lineage.network_parent`, `container.name|id|image`,
`ptrace.request`, `ptrace.target`, `bpf.cmd`.

**Lineage matrix** — each `lineage:` arm has `when` (one or many of
`network`/`interactive`/`trusted`/`unknown`/`any`), an optional `and:` guard, and
either `action: suppress` or a `severity`+`reason`(+`details`). A rule with arms
but no match is suppressed; a rule with no arms uses its top-level
`severity`/`reason`. This is how one rule id escalates or silences by ancestry —
exactly the behaviour of the original Go rules, now declarative.

**Operator workflow**
- **Override / append / add** — an overlay rule with `override: true` replaces a
  managed rule by id; `append: true` extends its `tags`/`exceptions`;
  `enabled: false` disables it; a new id adds a rule. `append_lists:` extends a
  built-in list.
- **Exceptions** — Falco-style per-rule carve-outs (`{name, fields, comps, values}`),
  evaluated after a match, in addition to the runtime suppression API.
- **Validate** — `kernelwatch --validate` compiles the embedded + operator ruleset
  and exits 0/1 (no root or eBPF needed — ideal for CI).
- **Hot reload** — when a custom ruleset is configured it is reloaded on a short
  interval; a broken file **fails fast at startup** but a broken **hot reload**
  keeps the last-good ruleset so the monitor never disarms.

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

## Host (whole-server) monitoring

With `KW_MONITOR_HOST=true`, KernelWatch also watches the **Docker host itself**
— an attacker who lands on the host (not a container) is the most valuable
target. Host monitoring is **opt-in and zero-impact when off**: host events are
dropped at the collector, so an existing container-only deployment is byte-for-
byte unchanged.

**Rollout (per host):** enable with `KW_MODE=monitor` for a ~48h tuning window,
tune the `KW_HOST_*` lists against what you see, then switch back to
`KW_MODE=alert`. Query host findings with `GET /api/v1/alerts?scope=host`.

### Host noise control

Host syscalls fire orders of magnitude more often than container ones. Instead
of the container **denylist**, host events pass an **allowlist** at the collector
(`internal/collector/hostfilter.go`):

- **`openat`** — delivered only for security-relevant paths (cron, systemd units,
  `ld.so.preload`, ssh/sudoers/pam config, `/var/log`, `docker.sock`,
  `authorized_keys`, cloud credentials…). Extra paths via
  `KW_HOST_OPEN_WATCH_EXTRA`.
- **`connect`/`clone`** — dropped (no host rule consumes them in v1).
- **`execve`** — kept, minus fleet agents you list in `KW_HOST_EXEC_EXCLUDE`
  (e.g. `node_exporter`, `datadog-agent`).
- KernelWatch's **own PID** is always excluded.

The allowlisted host opens (low volume) are then lineage-enriched like execve,
so host file rules can tell a **trusted writer** (`dpkg`, `apt`, `systemd`,
`cloud-init`, `logrotate`, `dockerd`…; extend via `KW_HOST_TRUSTED_WRITERS`)
from an attacker.

### Host lineage

A new class joins trusted/network-facing: **interactive admin session** (ancestry
contains `sshd`/`login`/`getty`/`tmux`/`screen`). `sudo` under `sshd` is daily
ops (suppressed); `sudo` under `nginx` is an incident. Network lineage still wins
over everything. Extra host-only trusted parents via `KW_HOST_TRUSTED_PARENTS`.

### Existing rules on the host

`reverse_shell` fires everywhere. `kernel_module_load`/`bpf_prog_load` suppress
trusted lineage (init/udev/dkms; dockerd/containerd) and are High. `persistence`
gains host paths and suppresses trusted writers. `sensitive_file` requires
**write-intent** on the host (reads of `/etc/passwd` etc. are constant).
`credential_file` matches as a substring so `/home/*/.aws/credentials` hits.
`network_tool`/`privilege_escalation` suppress `curl`/`sudo` in an interactive
session (but `nmap`/`masscan`/namespace tools still fire). `package_manager` on
the host fires **only** on network lineage (Critical). `shell_in_container` and
`container_drift` stay container-only (host analogs below).

### New host rules

| Rule id | Trigger | Severity | MITRE |
|---------|---------|----------|-------|
| `host_user_manipulation` | `execve` of `useradd`/`usermod`/`chpasswd`/`passwd`/… | interactive → Low, network → **Critical**, else Medium | T1136.001 |
| `host_log_tampering` | `shred`/`wipe` of `wtmp`/`btmp`/`*_history`; truncate/modify of `/var/log` by a non-log-writer | Medium–High | T1070 |
| `host_docker_sock` | `/var/run/docker.sock` opened by a non-Docker process (extend via `KW_HOST_DOCKER_CLIENTS`) | High | T1610 |
| `host_tmp_exec` | `execve` from `/tmp`, `/dev/shm`, `/var/tmp` (not `/run` — systemd uses it); build/package lineage suppressed | High | T1204.002 |
| `host_shell_from_service` | shell `execve` with network lineage on the host (RCE on a host-run nginx/node/java) | **Critical** | T1059 |

### SSH brute-force (auth-log tailer)

eBPF cannot see authentication **outcomes**, so SSH credential-stuffing is
detected by tailing the host auth log (`internal/logtail/`). Enable with
`KW_AUTHLOG_ENABLED=true` and point `KW_AUTHLOG_PATH` at the log (the Compose
file mounts `/var/log → /hostlog:ro`; use `/hostlog/auth.log` on Debian/Ubuntu or
`/hostlog/secure` on RHEL). It keeps a sliding window per source IP and
synthesizes a host-scope `ssh_bruteforce` alert (T1110.001) after
`KW_SSH_BRUTE_THRESHOLD` failures within `KW_SSH_BRUTE_WINDOW` seconds, into the
same alert/correlation/SIEM pipeline as eBPF findings.

### Delegated to the SIEM layer

KernelWatch deliberately does **not** do, leaving them to the surrounding stack:
file-integrity **hashing** (TOCTOU/perf trap — the write-intent persistence rules
are the high-signal 20%; use Wazuh/osquery for full FIM), **CIS benchmark / SCA**
(docker-bench-security / OpenSCAP), and **vulnerability scanning** (Trivy/Grype).

---

## Attack-chain correlation

A single suspicious syscall is often ambiguous; a **sequence** of them from the
same container's process tree is an intrusion in progress. The correlator
(`internal/correlator/`) keeps a short, per-container sliding window of findings,
scores each by severity (risk points: low=10, medium=25, high=50, critical=100),
and tracks the **distinct MITRE ATT&CK kill-chain stages** reached.

When a container crosses a threshold — `KW_CORRELATION_MIN_STAGES` distinct
stages **or** `KW_CORRELATION_MIN_SCORE` accumulated risk inside
`KW_CORRELATION_WINDOW` — it emits **one consolidated `attack_chain` incident**:

- severity **High**, escalating to **Critical** as the chain widens;
- a human reason listing the ordered stages (e.g. *Execution → Discovery →
  Credential Access → Persistence*) and the risk score;
- `details` carrying the contributing rule ids, stage list, finding count and
  window;
- tagged `attack-chain` — incidents **bypass** the severity filter and rate
  limiter so they are never dropped, and are re-emitted only when a **new** stage
  joins the chain (`KW_CORRELATION_COOLDOWN` guards against flapping).

This raises true-positive confidence and cuts alert fatigue: the operator sees
the campaign, not 30 disconnected lines. The engine is fully deterministic and
explainable — no learning phase. Disable with `KW_CORRELATION_ENABLED=false`.

## False-positive suppression

Three deterministic layers, applied in order:

1. **Lineage context** (above) — suppresses benign-by-ancestry activity.
2. **Config exceptions** (`KW_DETECTION_EXCEPTIONS`) — substring match against
   name/image/cmdline/ancestry; suppresses **all** rules for the event.
3. **Operator suppression rules** (`internal/suppress/`) — structured
   false-positive filters matched on `(rule_id, container_name, process_name,
   substring)`, ANDed so a more specific rule silences less. `scope` and
   `hostname` further **narrow** a rule (they cannot stand alone — no
   blanket-silencing a whole scope or host); `hostname` matters because a fleet
   shares one database, so silencing one noisy host must not mute the rest. They
   are swapped into the detector atomically and consulted before dedup, so a
   suppressed finding never even occupies a dedup slot, and are managed at runtime
   via the REST API.

Plus short-window **deduplication** by `(rule, container, pid)` and per-container
**rate limiting** (`KW_ALERT_MAX_RATE`/`KW_ALERT_RATE_WINDOW`).

## Output format (SIEM)

`KW_ALERT_FORMAT` selects the wire format for the log file and webhook body:
`native` (enriched KernelWatch JSON, default) or `ecs`
([Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/)). ECS maps
MITRE data onto `threat.*` and carries extras under `kernelwatch.*`, for drop-in
ingestion by Elastic Security and any ECS-aware SIEM.

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
