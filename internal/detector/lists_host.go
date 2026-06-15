package detector

// Host-scope detection lists. Every host file path matched here lives under a
// prefix/substring the collector's host openat allowlist delivers
// (collector.HostOpenWatched) — a test asserts this so the two cannot drift.

// hostPersistencePrefixes are host locations that, when WRITTEN, indicate an
// attacker establishing persistence or hijacking execution. Matched by path
// prefix on write-mode host open events.
var hostPersistencePrefixes = []string{
	"/etc/cron", "/var/spool/cron", // scheduled tasks (T1053.003)
	"/etc/systemd/", "/lib/systemd/system/", "/usr/lib/systemd/system/", // services (T1543.002)
	"/etc/init.d/", "/etc/rc.local", "/etc/update-motd.d/", "/etc/profile.d/", // boot/login hooks
	"/etc/ld.so.preload", "/etc/ld.so.conf", // library hijack / userland rootkit (T1574.006)
	"/etc/ssh/", // sshd_config* — login backdoors (T1556)
	"/etc/sudoers", "/etc/pam.d/", // privilege backdoors (T1556)
	"/etc/modules-load.d/", // boot-time module autoload
	"/root/.ssh/authorized_keys", // backdoor key for root (T1098.004)
}

// hostPersistenceSubstrings catch per-user paths under arbitrary home dirs.
var hostPersistenceSubstrings = []string{
	"/.ssh/authorized_keys", // backdoor key for any user (T1098.004)
}

// userMgmtTools are account-manipulation binaries (T1136.001 / T1098).
var userMgmtTools = set("useradd", "usermod", "userdel", "groupadd", "groupmod",
	"groupdel", "chpasswd", "passwd", "adduser", "deluser", "gpasswd")

// logTamperTools wipe/shred forensic artifacts (T1070).
var logTamperTools = set("shred", "wipe", "srm")

// logHistoryFiles are the high-value forensic/audit artifacts whose truncation
// or deletion is log tampering. Matched as a substring of the path.
var logHistoryFiles = []string{
	"wtmp", "btmp", "lastlog", "utmp", "auth.log", "secure", "audit.log",
	".bash_history", ".zsh_history", "_history",
}

// hostTmpExecDirs are ephemeral/writable locations a host binary should never be
// executed from. NOTE: /run is intentionally excluded — systemd legitimately
// execs helpers from /run on the host (unlike inside a container).
var hostTmpExecDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}

// buildLineage marks an ancestry chain as a build/package context, where exec
// from a temp dir is routine (compilers, package post-install scripts).
var buildLineageComms = set("dpkg", "apt", "apt-get", "rpm", "yum", "dnf", "make",
	"gcc", "cc", "go", "cargo", "npm", "yarn", "pip", "pip3", "cloud-init")

// dockerSockClients are comm names allowed to open the Docker control socket on
// the host without raising host_docker_sock. Extra clients via KW_HOST_DOCKER_CLIENTS.
var dockerSockClients = set("dockerd", "docker", "containerd", "containerd-shim",
	"containerd-shim-runc-v2", "runc", "com.docker.cli", "docker-compose",
	"docker-proxy", "kernelwatch")

// interactiveBenignPriv are privilege tools that are routine inside an
// interactive admin session and are suppressed there (sudo under sshd).
var interactiveBenignPriv = set("sudo", "su", "newgrp")
