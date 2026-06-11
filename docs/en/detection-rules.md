# Detection rules

The detector (`internal/detector/detector.go`) runs six rules against every
**container** event (host events are ignored). Rules run **in the order below**
and the **first match wins** — only one alert per event.

- **exec rules** match on the exact process name (`comm`, lower-cased) from an
  `execve` event.
- **file rules** match on a **path prefix** of the filename from an `openat` event.

Each alert carries a severity and a MITRE ATT&CK technique (TTP) + tactic.

---

## 1. Shell in container — `ruleShellInContainer`

- **Trigger:** an `execve` whose process name is exactly one of
  `sh`, `bash`, `zsh`, `fish`, `dash`, `ash`.
- **Severity:** High · **MITRE:** T1059 (Execution).
- **Why:** production containers should rarely, if ever, spawn an interactive
  shell. A shell often signals a hands-on-keyboard intrusion or a `docker exec`
  into a workload that shouldn't need one.

## 2. Privilege-escalation tool — `rulePrivilegedProcessInContainer`

- **Trigger:** an `execve` named `sudo`, `su`, `nsenter`, `unshare`, `chroot`,
  `capsh`, `setuid`, `newgrp`.
- **Severity:** High · **MITRE:** T1548 (Privilege Escalation).
- **Why:** these tools are used to gain higher privileges or break namespace
  isolation; `nsenter`/`unshare` in particular are container-escape primitives.

## 3. Sensitive-file access — `ruleSensitiveFileAccess`

- **Trigger:** an `openat` whose path starts with one of
  `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh`,
  `/var/run/docker.sock`, `/.dockerenv`, `/proc/sysrq-trigger`, `/proc/kcore`.
- **Severity:** Medium (T1005, Collection) — **escalated to Critical (T1611,
  Privilege Escalation)** when the path is exactly `/var/run/docker.sock`.
- **Why:** these files reveal credentials, host state or — in the case of the
  Docker socket — a direct path to full host takeover from inside a container.

## 4. Network recon tool — `ruleUnexpectedNetworkTool`

- **Trigger:** an `execve` named `nmap`, `masscan`, `netcat`, `nc`, `ncat`,
  `tcpdump`, `wireshark`, `tshark`, `curl`, `wget`.
- **Severity:** Medium, **High** for `nmap`/`masscan` · **MITRE:** T1046 (Discovery).
- **Why:** scanners/sniffers indicate lateral-movement reconnaissance; `curl`/`wget`
  frequently appear in post-exploitation download chains.

## 5. Package manager in a running container — `rulePackageManagerInContainer`

- **Trigger:** an `execve` named `apt`, `apt-get`, `dpkg`, `yum`, `dnf`, `rpm`,
  `apk`, `pip`, `pip3`, `npm`, `yarn`, `gem`.
- **Severity:** Medium · **MITRE:** T1072 (Execution).
- **Why:** installing packages at runtime is abnormal for immutable production
  images and often means an attacker is pulling in tooling.

## 6. Credential-file access — `ruleCredentialFileAccess`

- **Trigger:** an `openat` whose path starts with one of
  `/.env`, `/.aws/credentials`, `/.gcloud/credentials`, `/run/secrets`,
  `/.kube/config`.
- **Severity:** High · **MITRE:** T1552 (Credential Access).
- **Why:** classic credential-harvesting targets — cloud keys, Kubernetes configs,
  Docker secrets, app `.env` files.

---

## Severity threshold

Whether an alert is actually delivered also depends on `CS_ALERT_MIN_SEVERITY`
(see [configuration.md](configuration.md)). With the default `medium`, `low`
alerts would be suppressed — though none of the current rules emit `low`.

## Known matching limitations

- **Exact-name matching** means a renamed binary (e.g. `bash` copied to `xyz`)
  evades exec rules. Argument inspection is not yet implemented.
- **Prefix matching on the in-container path**: the filename is whatever the
  container passed to the syscall, which may be relative or differ from the host
  view; tighten paths cautiously.
- **First-match-only**: an event that satisfies two rules reports only the first in
  detector order. This keeps alerts de-duplicated but means rule ordering matters.

## Adding a rule

Implement a `func(collector.Event) *alerter.Alert`, returning `nil` when it does
not apply, and register it in `New()`'s slice. See
[development.md](development.md) for a worked example.
