package detector

import (
	"strings"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
)

// Rule is a detection rule that inspects an event and returns an alert if triggered.
type Rule func(event collector.Event) *alerter.Alert

// Detector applies a set of rules to incoming events.
type Detector struct {
	rules []Rule
}

// New creates a Detector with the default ruleset.
func New() *Detector {
	d := &Detector{}
	d.rules = []Rule{
		ruleShellInContainer,
		rulePrivilegedProcessInContainer,
		ruleSensitiveFileAccess,
		ruleUnexpectedNetworkTool,
		rulePackageManagerInContainer,
		ruleCredentialFileAccess,
	}
	return d
}

// Check runs all rules against an event and returns the first alert triggered.
// Returns nil if no rule fires.
func (d *Detector) Check(event collector.Event) *alerter.Alert {
	// Only check events from containers, not from the host
	if event.Container == nil {
		return nil
	}

	for _, rule := range d.rules {
		if alert := rule(event); alert != nil {
			alert.ContainerID   = event.Container.ID
			alert.ContainerName = event.Container.Name
			alert.ImageName     = event.Container.ImageName
			alert.PID           = event.PID
			alert.ProcessName   = processName(event)
			alert.Syscall       = event.TypeName()
			alert.Timestamp     = event.Timestamp
			return alert
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// baseName returns the final path element of a (possibly absolute) path.
func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// execBinary returns the lower-cased basename of the executed binary.
//
// IMPORTANT: at sys_enter_execve the process's `comm` still holds the *caller's*
// name (comm is updated only after the exec completes), so matching on
// e.ProcessName would miss the binary actually being launched. We key execve
// rules off the filename argument instead, falling back to comm if it's empty.
func execBinary(e collector.Event) string {
	name := e.Filename
	if name == "" {
		name = e.ProcessName
	}
	return strings.ToLower(baseName(name))
}

// processName picks the most meaningful process label for an alert: the executed
// binary for execve events, otherwise the kernel-reported comm.
func processName(e collector.Event) string {
	if e.Type == collector.EventExecve && e.Filename != "" {
		return baseName(e.Filename)
	}
	return e.ProcessName
}

// ── Rules ─────────────────────────────────────────────────────────────────────

// ruleShellInContainer fires when a shell is executed inside a container.
// Most production containers should never launch an interactive shell.
func ruleShellInContainer(e collector.Event) *alerter.Alert {
	if e.Type != collector.EventExecve {
		return nil
	}
	shells := []string{"sh", "bash", "zsh", "fish", "dash", "ash"}
	bin := execBinary(e)
	for _, shell := range shells {
		if bin == shell {
			return &alerter.Alert{
				Severity:    alerter.SeverityHigh,
				Reason:      "shell execution inside container",
				MITRETTP:    "T1059",
				MITRETactic: "Execution",
				Details: map[string]any{
					"shell": bin,
				},
			}
		}
	}
	return nil
}

// rulePrivilegedProcessInContainer fires when known privilege escalation
// tools are executed inside a container.
func rulePrivilegedProcessInContainer(e collector.Event) *alerter.Alert {
	if e.Type != collector.EventExecve {
		return nil
	}
	privTools := []string{
		"sudo", "su", "nsenter", "unshare",
		"chroot", "capsh", "setuid", "newgrp",
	}
	bin := execBinary(e)
	for _, tool := range privTools {
		if bin == tool {
			return &alerter.Alert{
				Severity:    alerter.SeverityHigh,
				Reason:      "privilege escalation tool executed in container",
				MITRETTP:    "T1548",
				MITRETactic: "Privilege Escalation",
				Details: map[string]any{
					"tool": bin,
				},
			}
		}
	}
	return nil
}

// ruleSensitiveFileAccess fires when a container process accesses
// files that should never be touched by an application container.
func ruleSensitiveFileAccess(e collector.Event) *alerter.Alert {
	if e.Type != collector.EventOpen {
		return nil
	}
	sensitivePaths := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/root/.ssh",
		"/var/run/docker.sock", // container escape vector
		"/.dockerenv",
		"/proc/sysrq-trigger",
		"/proc/kcore",
	}
	for _, path := range sensitivePaths {
		if strings.HasPrefix(e.Filename, path) {
			sev := alerter.SeverityMedium
			mitre := "T1005"
			tactic := "Collection"
			if e.Filename == "/var/run/docker.sock" {
				sev = alerter.SeverityCritical
				mitre = "T1611"
				tactic = "Privilege Escalation"
			}
			return &alerter.Alert{
				Severity:    sev,
				Reason:      "sensitive file accessed by container",
				MITRETTP:    mitre,
				MITRETactic: tactic,
				Details: map[string]any{
					"file": e.Filename,
				},
			}
		}
	}
	return nil
}

// ruleUnexpectedNetworkTool fires when network reconnaissance tools
// are executed inside a container.
func ruleUnexpectedNetworkTool(e collector.Event) *alerter.Alert {
	if e.Type != collector.EventExecve {
		return nil
	}
	netTools := []string{
		"nmap", "masscan", "netcat", "nc", "ncat",
		"tcpdump", "wireshark", "tshark",
		"curl", "wget", // common in post-exploit download chains
	}
	bin := execBinary(e)
	for _, tool := range netTools {
		if bin == tool {
			sev := alerter.SeverityMedium
			if tool == "nmap" || tool == "masscan" {
				sev = alerter.SeverityHigh
			}
			return &alerter.Alert{
				Severity:    sev,
				Reason:      "network tool executed inside container",
				MITRETTP:    "T1046",
				MITRETactic: "Discovery",
				Details: map[string]any{
					"tool": bin,
				},
			}
		}
	}
	return nil
}

// rulePackageManagerInContainer fires when a package manager is used
// inside a running container — often indicates an attacker installing tools.
func rulePackageManagerInContainer(e collector.Event) *alerter.Alert {
	if e.Type != collector.EventExecve {
		return nil
	}
	pkgManagers := []string{
		"apt", "apt-get", "dpkg",
		"yum", "dnf", "rpm",
		"apk", "pip", "pip3",
		"npm", "yarn", "gem",
	}
	bin := execBinary(e)
	for _, pm := range pkgManagers {
		if bin == pm {
			return &alerter.Alert{
				Severity:    alerter.SeverityMedium,
				Reason:      "package manager executed inside running container",
				MITRETTP:    "T1072",
				MITRETactic: "Execution",
				Details: map[string]any{
					"package_manager": bin,
				},
			}
		}
	}
	return nil
}

// ruleCredentialFileAccess fires when a container process reads
// files commonly targeted for credential harvesting.
func ruleCredentialFileAccess(e collector.Event) *alerter.Alert {
	if e.Type != collector.EventOpen {
		return nil
	}
	credFiles := []string{
		"/.env",
		"/.aws/credentials",
		"/.gcloud/credentials",
		"/run/secrets", // Docker secrets mount point
		"/.kube/config",
	}
	for _, path := range credFiles {
		if strings.HasPrefix(e.Filename, path) {
			return &alerter.Alert{
				Severity:    alerter.SeverityHigh,
				Reason:      "credential file accessed by container",
				MITRETTP:    "T1552",
				MITRETactic: "Credential Access",
				Details: map[string]any{
					"file": e.Filename,
				},
			}
		}
	}
	return nil
}
