package detector

import (
	"strings"

	"kernelwatch/internal/config"
)

// ── Binary category lists (detection-as-code) ───────────────────────────────
// Reusable value sets, Falco-style. Matched on the executed binary's basename.

var (
	shells       = set("sh", "bash", "zsh", "fish", "dash", "ash", "ksh", "tcsh")
	netTools     = set("nmap", "masscan", "netcat", "nc", "ncat", "socat", "tcpdump", "wireshark", "tshark", "curl", "wget")
	pkgManagers  = set("apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "apk", "pip", "pip3", "npm", "yarn", "gem")
	privTools    = set("sudo", "su", "nsenter", "unshare", "chroot", "capsh", "setuid", "newgrp")
	highNetTools = set("nmap", "masscan") // recon scanners — escalate even without lineage
)

// sensitiveFiles / credFiles are matched by path prefix on open events.
var sensitiveFiles = []string{
	"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh",
	"/var/run/docker.sock", "/.dockerenv", "/proc/sysrq-trigger", "/proc/kcore",
}

var credFiles = []string{
	"/.env", "/.aws/credentials", "/.gcloud/credentials", "/run/secrets", "/.kube/config",
}

// writableExecDirs are ephemeral/writable locations a legitimate image binary
// should never be executed from — strong drift / dropper signal.
var writableExecDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/"}

// persistenceFiles are locations that, when WRITTEN inside a container, indicate
// an attacker establishing persistence or hijacking execution. Matched by path
// prefix on write-mode open events.
var persistenceFiles = []string{
	"/etc/cron", "/var/spool/cron", // scheduled tasks (T1053.003)
	"/etc/systemd/", "/lib/systemd/system/", "/usr/lib/systemd/system/", // services (T1543.002)
	"/etc/init.d/", "/etc/rc.local", "/etc/update-motd.d/", "/etc/profile.d/", // boot/login hooks
	"/etc/ld.so.preload", "/etc/ld.so.conf", // library hijack / userland rootkit (T1574.006)
	"/root/.ssh/authorized_keys", // backdoor key (T1098.004)
	"/etc/sudoers.d/", "/etc/passwd", "/etc/shadow", // privilege backdoors
}

// open(2) flags (x86 Linux UAPI) used to tell a write-intent open from a read.
const (
	oWRONLY = 0x1
	oRDWR   = 0x2
	oCREAT  = 0x40
	oTRUNC  = 0x200
	oAPPEND = 0x400
	writeFlagMask = oWRONLY | oRDWR | oCREAT | oTRUNC | oAPPEND
)

// ── Process-lineage classification ──────────────────────────────────────────
// The decisive signal: the same binary is benign or malicious depending on its
// ancestry. Trusted ancestors are init systems / schedulers / container
// supervisors; network-facing ancestors are internet-exposed service runtimes
// where a spawned shell almost always means RCE / web-shell.

var defaultTrustedParents = []string{
	"init", "systemd", "cron", "crond", "anacron", "atd",
	"containerd-shim", "containerd-shim-runc-v2", "runc", "docker-init",
	"tini", "dumb-init", "s6-supervise", "s6-svscan", "supervisord", "runsv",
}

// Only dedicated, internet-facing server daemons belong here — NOT bare language
// runtimes. A web RCE always goes through the server process (php-fpm, gunicorn,
// puma, …), whereas the bare interpreter (`php artisan`, `python manage.py`,
// `ruby rake`) is routinely used by schedulers/queues/CLI tooling and would
// produce false positives if treated as network-facing.
var defaultNetworkParents = []string{
	"nginx", "apache2", "httpd", "caddy", "haproxy", "lighttpd",
	"php-fpm", "node", "java",
	"puma", "unicorn", "gunicorn", "uwsgi", "mongrel",
	"mysqld", "postgres", "redis-server", "memcached", "tomcat", "catalina.sh",
}

// defaultInteractiveParents mark an interactive administrator session. On the
// host, `sudo`/`su` under one of these is daily ops; the same under a service
// runtime is an incident. Network lineage still wins over interactive.
var defaultInteractiveParents = []string{
	"sshd", "login", "getty", "agetty", "mgetty",
	"tmux", "tmux: server", "screen", "systemd-logind",
}

// defaultHostTrustedWriters are processes that legitimately write to host
// persistence/config locations (package managers, init, cloud bootstrap, log
// rotation, the container runtime). A write under one of these is suppressed by
// the host persistence rules.
var defaultHostTrustedWriters = []string{
	"dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "unattended-upgrade",
	"rpm", "yum", "dnf", "zypper", "apk", "snapd", "snap",
	"systemd", "systemd-sysv-generator", "systemd-tmpfiles", "systemctl",
	"cloud-init", "logrotate", "rsyslogd", "journald", "systemd-journald",
	"dockerd", "containerd", "containerd-shim", "dkms", "kmod", "udevd", "systemd-udevd",
}

// classifier decides whether an event's ancestry is network-facing, an
// interactive admin session, or a trusted supervisor.
type classifier struct {
	trusted        map[string]bool // container-scope trusted supervisors/schedulers
	network        map[string]bool // network-facing service runtimes
	hostTrusted    map[string]bool // additional host-scope trusted parents
	interactive    map[string]bool // interactive admin session markers
	trustedWriters map[string]bool // host trusted package/system writers
	dockerClients  map[string]bool // comms allowed to open the docker socket on host
}

func newClassifier(cfg *config.Config) *classifier {
	c := &classifier{
		trusted:        map[string]bool{},
		network:        map[string]bool{},
		hostTrusted:    map[string]bool{},
		interactive:    map[string]bool{},
		trustedWriters: map[string]bool{},
		dockerClients:  map[string]bool{},
	}
	var extraTrusted, extraNetwork, hostParents, hostWriters, dockerClients []string
	if cfg != nil {
		extraTrusted, extraNetwork = cfg.TrustedParents, cfg.NetworkParents
		hostParents, hostWriters = cfg.HostTrustedParents, cfg.HostTrustedWriters
		dockerClients = cfg.HostDockerClients
	}
	fill := func(m map[string]bool, lists ...[]string) {
		for _, list := range lists {
			for _, p := range list {
				if s := strings.ToLower(strings.TrimSpace(p)); s != "" {
					m[s] = true
				}
			}
		}
	}
	fill(c.trusted, defaultTrustedParents, extraTrusted)
	fill(c.network, defaultNetworkParents, extraNetwork)
	fill(c.hostTrusted, hostParents)
	fill(c.interactive, defaultInteractiveParents)
	fill(c.trustedWriters, defaultHostTrustedWriters, hostWriters)
	for k := range dockerSockClients {
		c.dockerClients[k] = true
	}
	fill(c.dockerClients, dockerClients)
	return c
}

// isDockerClient reports whether a comm is an expected Docker-socket client.
func (c *classifier) isDockerClient(comm string) bool {
	return c.dockerClients[strings.ToLower(comm)]
}

// lineage classifies an ancestry chain. Precedence, highest first: network (a
// chain touching an internet-facing service is suspicious even if a scheduler is
// also above it) → interactive (an admin session) → trusted (supervisor/
// scheduler) → unknown.
type lineage int

const (
	lineageUnknown lineage = iota
	lineageTrusted
	lineageInteractive
	lineageNetwork
)

func (c *classifier) classify(ancestry []string, scope ruleScope) lineage {
	trusted, interactive := false, false
	for _, a := range ancestry {
		la := strings.ToLower(a)
		if c.network[la] {
			return lineageNetwork
		}
		if c.interactive[la] {
			interactive = true
		}
		if c.trusted[la] || (scope == scopeHost && c.hostTrusted[la]) {
			trusted = true
		}
	}
	if interactive {
		return lineageInteractive
	}
	if trusted {
		return lineageTrusted
	}
	return lineageUnknown
}

// trustedWriter reports whether the ancestry chain is a legitimate host writer
// (package manager, init, cloud bootstrap…) for the host persistence rules.
func (c *classifier) trustedWriter(ancestry []string) bool {
	for _, a := range ancestry {
		if c.trustedWriters[strings.ToLower(a)] {
			return true
		}
	}
	return false
}

// networkParent returns the first network-facing ancestor (for alert context).
func (c *classifier) networkParent(ancestry []string) string {
	for _, a := range ancestry {
		if c.network[strings.ToLower(a)] {
			return a
		}
	}
	return ""
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}
