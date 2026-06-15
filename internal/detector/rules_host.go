package detector

import (
	"strings"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
)

// Host-scope detection rules. These complement the cross-scope rules in
// rules.go for the things that only make sense on a whole server: account
// management, anti-forensics, the Docker control socket, temp-dir execution, and
// a service spawning a shell on the host itself.

// ruleHostUserManipulation fires on account-management binaries. In an
// interactive admin session this is routine (Low); driven by a network-facing
// service it is an attacker creating a backdoor account (Critical).
var ruleHostUserManipulation = Rule{
	ID: "host_user_manipulation", Desc: "User/group account manipulation on host",
	Severity: alerter.SeverityMedium, Scope: scopeHost, Tactic: "Persistence", Technique: "T1136.001",
	Tags: []string{"host", "accounts"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !userMgmtTools[bin] {
			return nil
		}
		switch c.classify(e.Ancestry, scope) {
		case lineageNetwork:
			return &hit{Severity: alerter.SeverityCritical,
				Reason:  "account manipulation by network-facing service (backdoor account)",
				Details: map[string]any{"tool": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		case lineageInteractive:
			return &hit{Severity: alerter.SeverityLow,
				Reason: "account management in interactive admin session", Details: map[string]any{"tool": bin}}
		default:
			return &hit{Reason: "account manipulation on host", Details: map[string]any{"tool": bin}}
		}
	},
}

// ruleHostLogTampering fires on anti-forensic activity: wiping forensic
// artifacts with shred/wipe, or truncating logs / shell histories by a process
// that is not a legitimate logging daemon.
var ruleHostLogTampering = Rule{
	ID: "host_log_tampering", Desc: "Log / forensic artifact tampering on host",
	Severity: alerter.SeverityMedium, Scope: scopeHost, Tactic: "Defense Evasion", Technique: "T1070",
	Tags: []string{"host", "anti-forensics"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		// (a) execve of a wipe tool — high if it targets a forensic artifact.
		if e.Type == collector.EventExecve {
			bin := execBinary(e)
			if !logTamperTools[bin] {
				return nil
			}
			if containsAny(strings.ToLower(e.CmdLine), logHistoryFiles) {
				return &hit{Severity: alerter.SeverityHigh,
					Reason: "forensic artifact wiped with shred/wipe", Details: map[string]any{"tool": bin, "cmdline": e.CmdLine}}
			}
			return &hit{Reason: "file-wiping tool executed on host", Details: map[string]any{"tool": bin}}
		}
		// (b) write/truncate open of a log or history file by a non-log-writer.
		if e.Type == collector.EventOpen && e.Arg1&writeFlagMask != 0 {
			isLog := strings.HasPrefix(e.Filename, "/var/log")
			isHist := containsAny(e.Filename, logHistoryFiles)
			if !isLog && !isHist {
				return nil
			}
			if c.trustedWriter(writerChain(e)) {
				return nil // rsyslogd/journald/logrotate
			}
			// Truncation (or touching a history/audit artifact) is the tamper
			// signal; a plain append to /var/log is ordinary logging.
			if e.Arg1&oTRUNC != 0 || isHist {
				return &hit{Severity: alerter.SeverityHigh,
					Reason: "log/forensic file truncated or modified on host", Details: map[string]any{"file": e.Filename}}
			}
			return &hit{Reason: "unexpected write to /var/log on host", Details: map[string]any{"file": e.Filename}}
		}
		return nil
	},
}

// ruleHostDockerSock fires when the Docker control socket is opened by a process
// that is not a known Docker client — a container-escape / lateral-movement
// primitive (anyone who can talk to docker.sock owns the host).
var ruleHostDockerSock = Rule{
	ID: "host_docker_sock", Desc: "Docker control socket opened by non-Docker process",
	Severity: alerter.SeverityHigh, Scope: scopeHost, Tactic: "Privilege Escalation", Technique: "T1610",
	Tags: []string{"host", "docker", "escape"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventOpen {
			return nil
		}
		if e.Filename != "/var/run/docker.sock" && e.Filename != "/run/docker.sock" {
			return nil
		}
		comm := processName(e)
		if c.isDockerClient(comm) {
			return nil
		}
		return &hit{Reason: "Docker control socket opened by non-Docker process on host (escape / lateral movement)",
			Details: map[string]any{"process": comm, "file": e.Filename}}
	},
}

// ruleHostTmpExec fires when a binary is executed from a world-writable temp
// directory on the host — a dropper/staged-payload signal. Build and package
// post-install lineage is suppressed (compilers and dpkg/rpm exec from temp dirs
// legitimately). NOTE: /run is excluded on purpose — systemd uses it.
var ruleHostTmpExec = Rule{
	ID: "host_tmp_exec", Desc: "Execution from a world-writable temp dir on host",
	Severity: alerter.SeverityHigh, Scope: scopeHost, Tactic: "Execution", Technique: "T1204.002",
	Tags: []string{"host", "drift"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		if e.Type != collector.EventExecve || e.Filename == "" {
			return nil
		}
		if !hasAnyPrefix(e.Filename, hostTmpExecDirs) {
			return nil
		}
		for _, a := range writerChain(e) {
			if buildLineageComms[strings.ToLower(a)] {
				return nil // make/gcc/dpkg/rpm post-install scripts
			}
		}
		if c.trustedWriter(writerChain(e)) {
			return nil
		}
		return &hit{Reason: "binary executed from world-writable temp dir on host", Details: map[string]any{"path": e.Filename}}
	},
}

// ruleHostShellFromService fires when a shell is spawned by a network-facing
// service running on the host itself (nginx/node/java on the box, not in a
// container) — the host-scope analog of shell_in_container's web-shell case.
var ruleHostShellFromService = Rule{
	ID: "host_shell_from_service", Desc: "Shell spawned by a network-facing service on host",
	Severity: alerter.SeverityCritical, Scope: scopeHost, Tactic: "Execution", Technique: "T1059",
	Tags: []string{"host", "shell", "rce"},
	Match: func(e collector.Event, c *classifier, scope ruleScope) *hit {
		bin := execBinary(e)
		if e.Type != collector.EventExecve || !shells[bin] {
			return nil
		}
		if c.classify(e.Ancestry, scope) == lineageNetwork {
			return &hit{Reason: "shell spawned by network-facing service on host (possible RCE)",
				Details: map[string]any{"shell": bin, "spawned_by": c.networkParent(e.Ancestry)}}
		}
		return nil
	},
}
