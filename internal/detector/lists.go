package detector

import "strings"

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

var defaultNetworkParents = []string{
	"nginx", "apache2", "httpd", "caddy", "haproxy", "lighttpd",
	"php-fpm", "php", "node", "python", "python3", "java", "ruby",
	"puma", "unicorn", "gunicorn", "uwsgi", "mongrel",
	"mysqld", "postgres", "redis-server", "memcached", "tomcat", "catalina.sh",
}

// classifier decides whether an event's ancestry is network-facing or trusted.
type classifier struct {
	trusted map[string]bool
	network map[string]bool
}

func newClassifier(extraTrusted, extraNetwork []string) *classifier {
	c := &classifier{trusted: map[string]bool{}, network: map[string]bool{}}
	for _, p := range append(append([]string{}, defaultTrustedParents...), extraTrusted...) {
		c.trusted[strings.ToLower(p)] = true
	}
	for _, p := range append(append([]string{}, defaultNetworkParents...), extraNetwork...) {
		c.network[strings.ToLower(p)] = true
	}
	return c
}

// lineage classifies an ancestry chain. network wins over trusted: a shell whose
// chain touches a network-facing service is suspicious even if cron is also
// somewhere above it.
type lineage int

const (
	lineageUnknown lineage = iota
	lineageTrusted
	lineageNetwork
)

func (c *classifier) classify(ancestry []string) lineage {
	trusted := false
	for _, a := range ancestry {
		la := strings.ToLower(a)
		if c.network[la] {
			return lineageNetwork
		}
		if c.trusted[la] {
			trusted = true
		}
	}
	if trusted {
		return lineageTrusted
	}
	return lineageUnknown
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
