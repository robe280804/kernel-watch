package container

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ResolveAncestry walks up the process tree from pid and returns the comm names
// of up to maxDepth ancestors, immediate parent first (e.g. ["sh","php-fpm",
// "containerd-shim"]). This is the core lineage signal: the same binary is
// benign or malicious depending on who launched it.
//
// Best-effort and userspace-only (reads /proc), matching the cgroup-resolution
// pattern in mapper.go — so the eBPF program needs no parent-pointer reads and
// stays CO-RE-free. Stops at PID 1 or when /proc is unavailable (e.g. the
// process already exited).
func ResolveAncestry(pid uint32, maxDepth int) []string {
	if maxDepth <= 0 {
		maxDepth = 5
	}
	ancestry := make([]string, 0, maxDepth)
	cur := pid
	for i := 0; i < maxDepth; i++ {
		ppid, ok := parentPID(cur)
		if !ok || ppid == 0 {
			break
		}
		if comm := procComm(ppid); comm != "" {
			ancestry = append(ancestry, comm)
		}
		if ppid <= 1 {
			break // reached init
		}
		cur = ppid
	}
	return ancestry
}

// parentPID reads /proc/<pid>/stat and returns the parent PID.
//
// The comm field (field 2) is wrapped in parentheses and may itself contain
// spaces or parentheses (e.g. "(my (weird) proc)"), so the only safe parse is
// to key off the LAST ')': everything after it is space-separated, and the
// fields are: state (3), ppid (4), ... — i.e. ppid is the 2nd token.
func parentPID(pid uint32) (uint32, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+1 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[rparen+1:]) // [state, ppid, pgrp, ...]
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(ppid), true
}

// procComm returns the command name of a PID from /proc/<pid>/comm.
func procComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
