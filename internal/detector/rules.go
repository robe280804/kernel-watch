package detector

import (
	"strings"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
)

// ruleScope is a bitmask of the scopes a rule applies to. A rule is evaluated
// only when the event's scope is in its mask, and its Match body branches on the
// passed scope for any per-scope behavior.
type ruleScope uint8

const (
	scopeContainer ruleScope = 1 << iota
	scopeHost
)

const scopeAll = scopeContainer | scopeHost

// Rule is a declarative detection unit (Falco-inspired): static metadata plus a
// Match function that returns a *hit when the event is suspicious. Returning nil
// means "no match" — including the deliberate suppression of benign lineage.
type Rule struct {
	ID        string
	Desc      string
	Severity  alerter.Severity // default; a hit may override (e.g. lineage escalation)
	Scope     ruleScope        // which scopes this rule applies to
	Tactic    string           // MITRE ATT&CK tactic
	Technique string           // MITRE ATT&CK technique id
	Tags      []string
	Match     func(e collector.Event, c *classifier, scope ruleScope) *hit
}

// hit is the result of a matched rule.
type hit struct {
	Severity alerter.Severity // overrides Rule.Severity when non-empty
	Reason   string
	Details  map[string]any
}

// defaultRules is the built-in ruleset, ordered high-signal first.
func defaultRules() []Rule {
	return []Rule{
		ruleKernelModuleLoad,
		ruleBPFProgLoad,
		ruleReverseShell,
		ruleProcessInjection,
		rulePersistence,
		ruleShellInContainer,
		rulePrivilegedProcess,
		ruleNetworkTool,
		ruleContainerDrift,
		rulePackageManager,
		ruleSensitiveFileAccess,
		ruleCredentialFileAccess,
		// Host-scope rules (rules_host.go).
		ruleHostUserManipulation,
		ruleHostLogTampering,
		ruleHostDockerSock,
		ruleHostTmpExec,
		ruleHostShellFromService,
	}
}

// ── execve rules (lineage-aware) ─────────────────────────────────────────────

var ruleShellInContainer = Rule{
	ID: "shell_in_container", Desc: "Shell executed inside a container",
	Severity: alerter.SeverityHigh, Scope: scopeContainer, Tactic: "Execution", Technique: "T1059",
	Tags: []string{"container", "shell"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !shells[bin] {
			return nil
		}
		switch c.classify(e.Ancestry, scope) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityCritical,
				Reason:  "interactive shell spawned by network-facing service (possible RCE/web-shell)",
				Details: map[string]any{"shell": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageTrusted:
			return nil // benign: cron/scheduler/entrypoint/supervisor
		default:
			return &hit{Reason: "shell execution inside container", Details: map[string]any{"shell": bin}}
		}
	},
}

var ruleNetworkTool = Rule{
	ID: "network_tool", Desc: "Network/recon tool executed",
	Severity: alerter.SeverityMedium, Scope: scopeAll, Tactic: "Discovery", Technique: "T1046",
	Tags: []string{"network"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !netTools[bin] {
			return nil
		}
		switch c.classify(e.Ancestry, scope) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityHigh,
				Reason:  "network tool spawned by network-facing service (possible post-exploitation)",
				Details: map[string]any{"tool": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageTrusted:
			return nil // benign: healthcheck/cron-driven curl/wget
		case lineageInteractive:
			// Admin running curl/wget in an SSH session is daily ops; recon
			// scanners (nmap/masscan) are not, regardless of who launched them.
			if highNetTools[bin] {
				return &hit{Severity: alerter.SeverityHigh,
					Reason: "recon scanner executed in interactive session", Details: map[string]any{"tool": bin}}
			}
			return nil
		default:
			sev := alerter.SeverityMedium
			if highNetTools[bin] {
				sev = alerter.SeverityHigh
			}
			return &hit{Severity: sev, Reason: "network tool executed", Details: map[string]any{"tool": bin}}
		}
	},
}

var rulePackageManager = Rule{
	ID: "package_manager", Desc: "Package manager executed in a running environment",
	Severity: alerter.SeverityMedium, Scope: scopeAll, Tactic: "Execution", Technique: "T1072",
	Tags: []string{"package-manager"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !pkgManagers[bin] {
			return nil
		}
		switch c.classify(e.Ancestry, scope) {
		case lineageNetwork:
			// A package manager driven by a network-facing service is an attacker
			// installing tools — and on the host that is the only case worth firing.
			sev := alerter.SeverityHigh
			if scope == scopeHost {
				sev = alerter.SeverityCritical
			}
			return &hit{Severity: sev,
				Reason:  "package manager spawned by network-facing service (attacker installing tools)",
				Details: map[string]any{"package_manager": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		default:
			// On the host, routine admin/cron/unattended package operations are
			// constant — only the network-lineage case above is interesting.
			if scope == scopeHost {
				return nil
			}
			if c.classify(e.Ancestry, scope) == lineageTrusted {
				return nil // benign: unattended-upgrades / image-build style cron jobs
			}
			return &hit{Reason: "package manager executed inside running container", Details: map[string]any{"package_manager": bin}}
		}
	},
}

var rulePrivilegedProcess = Rule{
	ID: "privilege_escalation", Desc: "Privilege-escalation tool executed",
	Severity: alerter.SeverityHigh, Scope: scopeAll, Tactic: "Privilege Escalation", Technique: "T1548",
	Tags: []string{"privesc"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !privTools[bin] {
			return nil
		}
		switch c.classify(e.Ancestry, scope) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityCritical,
				Reason:  "privilege escalation tool spawned by network-facing service",
				Details: map[string]any{"tool": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageTrusted:
			return nil
		case lineageInteractive:
			// sudo/su in an admin SSH session is every login; namespace/chroot
			// tooling is not, so those still fire.
			if interactiveBenignPriv[bin] {
				return nil
			}
			return &hit{Reason: "privilege/namespace tool executed in interactive session", Details: map[string]any{"tool": bin}}
		default:
			return &hit{Reason: "privilege escalation tool executed", Details: map[string]any{"tool": bin}}
		}
	},
}

// ruleReverseShell fires on argv signatures that are essentially never benign,
// regardless of lineage or scope.
var ruleReverseShell = Rule{
	ID: "reverse_shell", Desc: "Reverse-shell / remote-exec pattern in command line",
	Severity: alerter.SeverityCritical, Scope: scopeAll, Tactic: "Execution", Technique: "T1059",
	Tags: []string{"reverse-shell", "c2"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventExecve || e.CmdLine == "" {
			return nil
		}
		cl := strings.ToLower(e.CmdLine)
		for _, sig := range []string{"/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "nc -c", "pty.spawn", "socket.socket"} {
			if strings.Contains(cl, sig) {
				return &hit{Reason: "reverse-shell pattern detected in command line", Details: map[string]any{"cmdline": e.CmdLine, "signature": sig}}
			}
		}
		// piped downloader → shell: curl/wget … | sh|bash
		if strings.Contains(cl, "curl ") || strings.Contains(cl, "wget ") {
			for _, p := range []string{"|sh", "| sh", "|bash", "| bash"} {
				if strings.Contains(cl, p) {
					return &hit{Reason: "remote payload piped to shell (download-and-execute)", Details: map[string]any{"cmdline": e.CmdLine}}
				}
			}
		}
		return nil
	},
}

// ruleContainerDrift fires when a binary is executed from a writable/ephemeral
// path inside a container — a high-precision indicator of a runtime-introduced
// executable (dropper, miner, staged payload). The host analog is host_tmp_exec
// (which excludes /run, since systemd legitimately uses it on the host).
var ruleContainerDrift = Rule{
	ID: "container_drift", Desc: "Execution of a binary from a writable/ephemeral path",
	Severity: alerter.SeverityHigh, Scope: scopeContainer, Tactic: "Defense Evasion", Technique: "T1036",
	Tags: []string{"container", "drift"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventExecve || e.Filename == "" {
			return nil
		}
		for _, dir := range writableExecDirs {
			if strings.HasPrefix(e.Filename, dir) {
				return &hit{Reason: "binary executed from writable/ephemeral path", Details: map[string]any{"path": e.Filename}}
			}
		}
		return nil
	},
}

// ── persistence / kernel-tampering rules ─────────────────────────────────────

// rulePersistence fires on a WRITE-mode open of a location used to survive
// reboots or hijack execution (cron, systemd units, ld.so.preload, ssh keys…).
// On the host it uses a broader path set and suppresses trusted writers
// (package managers, init, cloud bootstrap).
var rulePersistence = Rule{
	ID: "persistence", Desc: "Write to a persistence-sensitive location",
	Severity: alerter.SeverityHigh, Scope: scopeAll, Tactic: "Persistence", Technique: "T1543",
	Tags: []string{"persistence"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventOpen || e.Arg1&writeFlagMask == 0 {
			return nil // not an open, or read-only
		}
		matched := false
		if scope == scopeHost {
			matched = hasAnyPrefix(e.Filename, hostPersistencePrefixes) ||
				containsAny(e.Filename, hostPersistenceSubstrings)
		} else {
			matched = hasAnyPrefix(e.Filename, persistenceFiles)
		}
		if !matched {
			return nil
		}
		// On the host, package managers / init / cloud-init write units, cron
		// entries and ssh config all the time — suppress those.
		if scope == scopeHost && c.trustedWriter(writerChain(e)) {
			return nil
		}
		sev := alerter.SeverityHigh
		// ld.so.preload is the classic userland-rootkit hook → critical.
		if strings.HasPrefix(e.Filename, "/etc/ld.so.preload") {
			sev = alerter.SeverityCritical
		}
		return &hit{Severity: sev, Reason: "write to persistence-sensitive location", Details: map[string]any{"file": e.Filename}}
	},
}

// ruleProcessInjection fires on ptrace requests used to read/write or hijack
// another process's memory (code injection, credential theft).
var ruleProcessInjection = Rule{
	ID: "process_injection", Desc: "ptrace-based process injection/manipulation",
	Severity: alerter.SeverityHigh, Scope: scopeAll, Tactic: "Privilege Escalation", Technique: "T1055.008",
	Tags: []string{"injection"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventPtrace {
			return nil
		}
		// PTRACE_POKETEXT=4, POKEDATA=5, POKEUSR=6, SETREGS=13, ATTACH=16, SEIZE=0x4206.
		switch e.Arg1 {
		case 4, 5, 6, 13, 16, 0x4206:
			return &hit{Reason: "ptrace process injection/manipulation", Details: map[string]any{"request": e.Arg1, "target_pid": e.Arg2}}
		}
		return nil
	},
}

// ruleKernelModuleLoad fires when a kernel module is loaded. From a container
// this is almost always a rootkit (Critical); on the host, init/udev/dkms load
// modules legitimately, so trusted lineage is suppressed and the rest is High.
var ruleKernelModuleLoad = Rule{
	ID: "kernel_module_load", Desc: "Kernel module loaded",
	Severity: alerter.SeverityCritical, Scope: scopeAll, Tactic: "Persistence", Technique: "T1547.006",
	Tags: []string{"rootkit", "kernel"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventModule {
			return nil
		}
		if scope == scopeHost {
			if c.trustedWriter(writerChain(e)) || c.classify(e.Ancestry, scope) == lineageTrusted {
				return nil // systemd/udevd/kmod/dkms loading a module
			}
			return &hit{Severity: alerter.SeverityHigh, Reason: "kernel module loaded on host from untrusted lineage (possible rootkit)"}
		}
		return &hit{Reason: "kernel module loaded from container (possible rootkit)"}
	},
}

// ruleBPFProgLoad fires when an eBPF program is loaded. Application containers
// should never do this (High); on a Docker host, systemd/dockerd/containerd load
// BPF legitimately, so trusted lineage is suppressed.
var ruleBPFProgLoad = Rule{
	ID: "bpf_prog_load", Desc: "eBPF program loaded",
	Severity: alerter.SeverityHigh, Scope: scopeAll, Tactic: "Defense Evasion", Technique: "T1562.001",
	Tags: []string{"ebpf", "evasion"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		const bpfProgLoad = 5 // BPF_PROG_LOAD
		if e.Type != collector.EventBPF || e.Arg1 != bpfProgLoad {
			return nil
		}
		if scope == scopeHost && c.trustedWriter(writerChain(e)) {
			return nil // dockerd/containerd/systemd load BPF on Docker hosts
		}
		return &hit{Reason: "eBPF program loaded (possible evasion/rootkit)", Details: map[string]any{"bpf_cmd": e.Arg1}}
	},
}

// ── open rules (path-based) ──────────────────────────────────────────────────

var ruleSensitiveFileAccess = Rule{
	ID: "sensitive_file", Desc: "Sensitive file accessed",
	Severity: alerter.SeverityMedium, Scope: scopeAll, Tactic: "Collection", Technique: "T1005",
	Tags: []string{"file"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventOpen {
			return nil
		}
		if scope == scopeHost {
			// Host reads of /etc/passwd, /etc/shadow, sudoers etc. are constant
			// (NSS, sudo, sshd) — only a WRITE is interesting. docker.sock and ssh
			// keys are owned by the dedicated host rules.
			if e.Arg1&writeFlagMask == 0 {
				return nil
			}
			if e.Filename == "/var/run/docker.sock" || strings.HasPrefix(e.Filename, "/root/.ssh") {
				return nil
			}
		}
		for _, p := range sensitiveFiles {
			if strings.HasPrefix(e.Filename, p) {
				if e.Filename == "/var/run/docker.sock" {
					return &hit{Severity: alerter.SeverityCritical, Reason: "docker socket accessed by container (container-escape vector)", Details: map[string]any{"file": e.Filename}}
				}
				return &hit{Reason: "sensitive file accessed", Details: map[string]any{"file": e.Filename}}
			}
		}
		return nil
	},
}

var ruleCredentialFileAccess = Rule{
	ID: "credential_file", Desc: "Credential file accessed",
	Severity: alerter.SeverityHigh, Scope: scopeAll, Tactic: "Credential Access", Technique: "T1552",
	Tags: []string{"credentials"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventOpen {
			return nil
		}
		// Substring (not prefix) match so per-user paths like
		// /home/<user>/.aws/credentials hit on the host too.
		if containsAny(e.Filename, credFiles) {
			return &hit{Reason: "credential file accessed", Details: map[string]any{"file": e.Filename}}
		}
		return nil
	},
}

// ── helpers ──────────────────────────────────────────────────────────────────

// baseName returns the final path element.
func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// execBinary returns the lower-cased basename of the executed binary. At
// sys_enter_execve comm holds the caller's name, so we key off Filename (argv[0]
// captured by eBPF), falling back to comm if empty.
func execBinary(e collector.Event) string {
	name := e.Filename
	if name == "" {
		name = e.ProcessName
	}
	return strings.ToLower(baseName(name))
}

// processName picks the most meaningful process label for an alert.
func processName(e collector.Event) string {
	if e.Type == collector.EventExecve && e.Filename != "" {
		return baseName(e.Filename)
	}
	return e.ProcessName
}

// writerChain is the process's own comm followed by its ancestry — the full set
// of names a "is this a trusted writer?" check should consider, since the acting
// process (e.g. dpkg, rsyslogd) is itself the writer, not an ancestor.
func writerChain(e collector.Event) []string {
	return append([]string{e.ProcessName}, e.Ancestry...)
}

// hasAnyPrefix reports whether s starts with any of the given prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
