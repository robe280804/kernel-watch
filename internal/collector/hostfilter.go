package collector

import (
	"os"
	"strings"

	"kernelwatch/internal/config"
)

// hostFilter is the host-scope noise gate. Host syscalls fire orders of
// magnitude more often than container ones (systemd, cron, NSS lookups, every
// login shell), so — unlike container opens, which use the isNoisyPath denylist
// — host events pass through an ALLOWLIST: only security-relevant paths and the
// high-signal syscalls survive. This keeps host monitoring affordable on a busy
// server while still seeing what matters.
type hostFilter struct {
	selfPID     uint32
	execExclude map[string]bool // comm/binary basenames to ignore (fleet agents)
	openExtra   []string        // operator-supplied extra open-path substrings
}

// newHostFilter builds the gate from config. Always constructed (cheap); only
// consulted for host-scope events.
func newHostFilter(cfg *config.Config) *hostFilter {
	hf := &hostFilter{
		selfPID:     uint32(os.Getpid()),
		execExclude: map[string]bool{},
		openExtra:   cfg.HostOpenWatchExtra,
	}
	for _, c := range cfg.HostExecExclude {
		if s := strings.ToLower(strings.TrimSpace(c)); s != "" {
			hf.execExclude[s] = true
		}
	}
	return hf
}

// keep reports whether a host-scope event is worth delivering to the detector.
func (h *hostFilter) keep(e *Event) bool {
	// Never report KernelWatch's own activity — visible thanks to pid:host.
	if e.PID == h.selfPID {
		return false
	}
	switch e.Type {
	case EventOpen:
		return HostOpenWatched(e.Filename) || containsAny(e.Filename, h.openExtra)
	case EventConnect, EventClone:
		// No host rule consumes these in v1; dropping them removes the bulk of
		// host syscall volume.
		return false
	case EventExecve:
		if h.execExclude[strings.ToLower(e.ProcessName)] ||
			h.execExclude[strings.ToLower(baseNameHF(e.Filename))] {
			return false
		}
		return true
	default:
		// ptrace / init_module / bpf — always high-signal, keep.
		return true
	}
}

// hostOpenWatchPrefixes is the allowlist of path PREFIXES whose host-scope
// openat events are delivered. The detector's host file rules only ever match
// paths under these prefixes (or the substrings below); a detector test asserts
// that so the two lists cannot silently drift.
var hostOpenWatchPrefixes = []string{
	"/etc/cron", "/var/spool/cron", // scheduled tasks
	"/etc/systemd/", "/lib/systemd/system/", "/usr/lib/systemd/system/", // units
	"/etc/init.d/", "/etc/rc.local", "/etc/update-motd.d/", "/etc/profile.d/", // boot/login hooks
	"/etc/ld.so.preload", "/etc/ld.so.conf", // library hijack
	"/etc/ssh/", "/etc/sudoers", "/etc/pam.d/", "/etc/modules-load.d/", // auth / module config
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", // account databases
	"/root/.ssh", // root backdoor key
	"/var/log",   // log tampering
	"/var/run/docker.sock", "/run/docker.sock", // docker control socket
}

// hostOpenWatchSubstrings are matched anywhere in the path so per-user paths
// (under arbitrary /home/<user>) are covered without allowing all of /home,
// which would flood (every login shell reads its dotfiles).
var hostOpenWatchSubstrings = []string{
	"/.ssh/authorized_keys",
	"/.aws/credentials",
	"/.gcloud/credentials",
	"/.kube/config",
}

// HostOpenWatched reports whether a host openat path is on the allowlist. It is
// exported so the detector can assert (in a test) that every path its host
// rules match is one the collector will actually deliver.
func HostOpenWatched(path string) bool {
	for _, p := range hostOpenWatchPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return containsAny(path, hostOpenWatchSubstrings)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// baseNameHF returns the final path element (local copy to avoid importing the
// detector, which would create a cycle).
func baseNameHF(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}
