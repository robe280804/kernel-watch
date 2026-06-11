package detector

import (
	"strings"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
)

// Rule is a declarative detection unit (Falco-inspired): static metadata plus a
// Match function that returns a *hit when the event is suspicious. Returning nil
// means "no match" — including the deliberate suppression of benign lineage.
type Rule struct {
	ID        string
	Desc      string
	Severity  alerter.Severity // default; a hit may override (e.g. lineage escalation)
	Tactic    string           // MITRE ATT&CK tactic
	Technique string           // MITRE ATT&CK technique id
	Tags      []string
	Match     func(e collector.Event, c *classifier) *hit
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
	}
}

// ── execve rules (lineage-aware) ─────────────────────────────────────────────

var ruleShellInContainer = Rule{
	ID: "shell_in_container", Desc: "Shell executed inside a container",
	Severity: alerter.SeverityHigh, Tactic: "Execution", Technique: "T1059",
	Tags: []string{"container", "shell"},
	Match: func(e collector.Event, c *classifier) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !shells[bin] {
			return nil
		}
		switch c.classify(e.Ancestry) {
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
	ID: "network_tool", Desc: "Network/recon tool executed inside a container",
	Severity: alerter.SeverityMedium, Tactic: "Discovery", Technique: "T1046",
	Tags: []string{"container", "network"},
	Match: func(e collector.Event, c *classifier) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !netTools[bin] {
			return nil
		}
		switch c.classify(e.Ancestry) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityHigh,
				Reason:  "network tool spawned by network-facing service (possible post-exploitation)",
				Details: map[string]any{"tool": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageTrusted:
			return nil // benign: healthcheck/cron-driven curl/wget
		default:
			sev := alerter.SeverityMedium
			if highNetTools[bin] {
				sev = alerter.SeverityHigh
			}
			return &hit{Severity: sev, Reason: "network tool executed inside container", Details: map[string]any{"tool": bin}}
		}
	},
}

var rulePackageManager = Rule{
	ID: "package_manager", Desc: "Package manager executed inside a running container",
	Severity: alerter.SeverityMedium, Tactic: "Execution", Technique: "T1072",
	Tags: []string{"container", "package-manager"},
	Match: func(e collector.Event, c *classifier) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !pkgManagers[bin] {
			return nil
		}
		switch c.classify(e.Ancestry) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityHigh,
				Reason:  "package manager spawned by network-facing service (attacker installing tools)",
				Details: map[string]any{"package_manager": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageTrusted:
			return nil // benign: unattended-upgrades / image-build style cron jobs
		default:
			return &hit{Reason: "package manager executed inside running container", Details: map[string]any{"package_manager": bin}}
		}
	},
}

var rulePrivilegedProcess = Rule{
	ID: "privilege_escalation", Desc: "Privilege-escalation tool executed in a container",
	Severity: alerter.SeverityHigh, Tactic: "Privilege Escalation", Technique: "T1548",
	Tags: []string{"container", "privesc"},
	Match: func(e collector.Event, c *classifier) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !privTools[bin] {
			return nil
		}
		switch c.classify(e.Ancestry) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityCritical,
				Reason:  "privilege escalation tool spawned by network-facing service",
				Details: map[string]any{"tool": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageTrusted:
			return nil
		default:
			return &hit{Reason: "privilege escalation tool executed in container", Details: map[string]any{"tool": bin}}
		}
	},
}

// ruleReverseShell fires on argv signatures that are essentially never benign,
// regardless of lineage.
var ruleReverseShell = Rule{
	ID: "reverse_shell", Desc: "Reverse-shell / remote-exec pattern in command line",
	Severity: alerter.SeverityCritical, Tactic: "Execution", Technique: "T1059",
	Tags: []string{"container", "reverse-shell", "c2"},
	Match: func(e collector.Event, c *classifier) *hit {
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
// path — a high-precision indicator of a runtime-introduced executable (dropper,
// miner, staged payload) that was never part of the immutable image.
//
// NOTE: argv[0]-vs-path masquerade detection (T1036.005) was intentionally left
// out of this first cut: login shells ("-bash") and busybox applets routinely
// have argv[0] differ from the exec path, which would generate false positives.
// Image-manifest comparison is the precise way to do drift and is a Phase 3 item.
var ruleContainerDrift = Rule{
	ID: "container_drift", Desc: "Execution of a binary from a writable/ephemeral path",
	Severity: alerter.SeverityHigh, Tactic: "Defense Evasion", Technique: "T1036",
	Tags: []string{"container", "drift"},
	Match: func(e collector.Event, c *classifier) *hit {
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
var rulePersistence = Rule{
	ID: "persistence", Desc: "Write to a persistence-sensitive location",
	Severity: alerter.SeverityHigh, Tactic: "Persistence", Technique: "T1543",
	Tags: []string{"container", "persistence"},
	Match: func(e collector.Event, c *classifier) *hit {
		if e.Type != collector.EventOpen || e.Arg1&writeFlagMask == 0 {
			return nil // not an open, or read-only
		}
		for _, p := range persistenceFiles {
			if strings.HasPrefix(e.Filename, p) {
				sev := alerter.SeverityHigh
				// ld.so.preload is the classic userland-rootkit hook → critical.
				if strings.HasPrefix(e.Filename, "/etc/ld.so.preload") {
					sev = alerter.SeverityCritical
				}
				return &hit{Severity: sev, Reason: "write to persistence-sensitive location", Details: map[string]any{"file": e.Filename}}
			}
		}
		return nil
	},
}

// ruleProcessInjection fires on ptrace requests used to read/write or hijack
// another process's memory (code injection, credential theft).
var ruleProcessInjection = Rule{
	ID: "process_injection", Desc: "ptrace-based process injection/manipulation",
	Severity: alerter.SeverityHigh, Tactic: "Privilege Escalation", Technique: "T1055.008",
	Tags: []string{"container", "injection"},
	Match: func(e collector.Event, c *classifier) *hit {
		if e.Type != collector.EventPtrace {
			return nil
		}
		// PTRACE_POKETEXT=4, POKEDATA=5, POKEUSR=6, SETREGS=13, ATTACH=16, SEIZE=0x4206.
		switch e.Arg1 {
		case 4, 5, 6, 13, 16, 0x4206:
			return &hit{Reason: "ptrace process injection/manipulation inside container", Details: map[string]any{"request": e.Arg1, "target_pid": e.Arg2}}
		}
		return nil
	},
}

// ruleKernelModuleLoad fires when a container loads a kernel module — almost
// always a rootkit or kernel-level tampering attempt.
var ruleKernelModuleLoad = Rule{
	ID: "kernel_module_load", Desc: "Kernel module loaded from a container",
	Severity: alerter.SeverityCritical, Tactic: "Persistence", Technique: "T1547.006",
	Tags: []string{"container", "rootkit", "kernel"},
	Match: func(e collector.Event, c *classifier) *hit {
		if e.Type != collector.EventModule {
			return nil
		}
		return &hit{Reason: "kernel module loaded from container (possible rootkit)"}
	},
}

// ruleBPFProgLoad fires when a container loads an eBPF program (bpf(BPF_PROG_LOAD))
// — a powerful defense-evasion / kernel-rootkit primitive that application
// containers should never use.
var ruleBPFProgLoad = Rule{
	ID: "bpf_prog_load", Desc: "eBPF program loaded from a container",
	Severity: alerter.SeverityHigh, Tactic: "Defense Evasion", Technique: "T1562.001",
	Tags: []string{"container", "ebpf", "evasion"},
	Match: func(e collector.Event, c *classifier) *hit {
		const bpfProgLoad = 5 // BPF_PROG_LOAD
		if e.Type != collector.EventBPF || e.Arg1 != bpfProgLoad {
			return nil
		}
		return &hit{Reason: "eBPF program loaded from container (possible evasion/rootkit)", Details: map[string]any{"bpf_cmd": e.Arg1}}
	},
}

// ── open rules (path-based; no lineage) ──────────────────────────────────────

var ruleSensitiveFileAccess = Rule{
	ID: "sensitive_file", Desc: "Sensitive file accessed by a container",
	Severity: alerter.SeverityMedium, Tactic: "Collection", Technique: "T1005",
	Tags: []string{"container", "file"},
	Match: func(e collector.Event, c *classifier) *hit {
		if e.Type != collector.EventOpen {
			return nil
		}
		for _, p := range sensitiveFiles {
			if strings.HasPrefix(e.Filename, p) {
				if e.Filename == "/var/run/docker.sock" {
					return &hit{Severity: alerter.SeverityCritical, Reason: "docker socket accessed by container (container-escape vector)", Details: map[string]any{"file": e.Filename}}
				}
				return &hit{Reason: "sensitive file accessed by container", Details: map[string]any{"file": e.Filename}}
			}
		}
		return nil
	},
}

var ruleCredentialFileAccess = Rule{
	ID: "credential_file", Desc: "Credential file accessed by a container",
	Severity: alerter.SeverityHigh, Tactic: "Credential Access", Technique: "T1552",
	Tags: []string{"container", "credentials"},
	Match: func(e collector.Event, c *classifier) *hit {
		if e.Type != collector.EventOpen {
			return nil
		}
		for _, p := range credFiles {
			if strings.HasPrefix(e.Filename, p) {
				return &hit{Reason: "credential file accessed by container", Details: map[string]any{"file": e.Filename}}
			}
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
