package ruleengine

import (
	"strings"

	"kernelwatch/internal/collector"
)

// open(2) flags (x86 Linux UAPI) — kept local so the engine has no dependency on
// the detector. Must match internal/detector/lists.go.
const (
	oWRONLY       = 0x1
	oRDWR         = 0x2
	oCREAT        = 0x40
	oTRUNC        = 0x200
	oAPPEND       = 0x400
	writeFlagMask = oWRONLY | oRDWR | oCREAT | oTRUNC | oAPPEND
)

// evalCtx wraps one event for evaluation, caching the two relatively expensive
// derived values (lineage classification and exec basename) so a rule's gate
// condition and all its lineage arms share one computation.
type evalCtx struct {
	e     *collector.Event
	c     LineageProvider
	scope Scope

	lin     Lineage
	linDone bool
	base    string
	baseDone bool
}

func newEvalCtx(e *collector.Event, c LineageProvider, scope Scope) *evalCtx {
	return &evalCtx{e: e, c: c, scope: scope}
}

func (cx *evalCtx) lineage() Lineage {
	if !cx.linDone {
		cx.lin = cx.c.Classify(cx.e.Ancestry, cx.scope == ScopeHost)
		cx.linDone = true
	}
	return cx.lin
}

func (cx *evalCtx) execBase() string {
	if !cx.baseDone {
		name := cx.e.Filename
		if name == "" {
			name = cx.e.ProcessName
		}
		cx.base = strings.ToLower(baseName(name))
		cx.baseDone = true
	}
	return cx.base
}

func (cx *evalCtx) chain() []string {
	return append([]string{cx.e.ProcessName}, cx.e.Ancestry...)
}

// ── String fields ─────────────────────────────────────────────────────────────

type strAccessor func(*evalCtx) string

var strFields = map[string]strAccessor{
	"evt.type":               func(cx *evalCtx) string { return typeName(cx.e.Type) },
	"proc.name":              func(cx *evalCtx) string { return processName(cx.e) },
	"proc.exe_base":          func(cx *evalCtx) string { return cx.execBase() },
	"proc.exe_path":          func(cx *evalCtx) string { return cx.e.Filename },
	"proc.cmdline":           func(cx *evalCtx) string { return cx.e.CmdLine },
	"proc.cmdline_lc":        func(cx *evalCtx) string { return strings.ToLower(cx.e.CmdLine) },
	"fd.name":                func(cx *evalCtx) string { return cx.e.Filename },
	"fd.directory":           func(cx *evalCtx) string { return dirName(cx.e.Filename) },
	"scope":                  func(cx *evalCtx) string { return scopeName(cx.scope) },
	"lineage":                func(cx *evalCtx) string { return cx.lineage().String() },
	"lineage.network_parent": func(cx *evalCtx) string { return cx.c.NetworkParent(cx.e.Ancestry) },
	"container.name":         func(cx *evalCtx) string { return containerField(cx, 0) },
	"container.id":           func(cx *evalCtx) string { return containerField(cx, 1) },
	"container.image":        func(cx *evalCtx) string { return containerField(cx, 2) },
}

func containerField(cx *evalCtx, which int) string {
	if cx.e.Container == nil {
		return ""
	}
	switch which {
	case 0:
		return cx.e.Container.Name
	case 1:
		return cx.e.Container.ID
	default:
		return cx.e.Container.ImageName
	}
}

// ── Int fields ────────────────────────────────────────────────────────────────

type intAccessor func(*evalCtx) int64

var intFields = map[string]intAccessor{
	"ptrace.request": func(cx *evalCtx) int64 { return int64(cx.e.Arg1) },
	"ptrace.target":  func(cx *evalCtx) int64 { return int64(cx.e.Arg2) },
	"bpf.cmd":        func(cx *evalCtx) int64 { return int64(cx.e.Arg1) },
}

// ── Bool fields ───────────────────────────────────────────────────────────────

type boolAccessor func(*evalCtx) bool

var boolFields = map[string]boolAccessor{
	"evt.is_open_write": func(cx *evalCtx) bool {
		return cx.e.Type == collector.EventOpen && cx.e.Arg1&writeFlagMask != 0
	},
	"evt.is_open_trunc": func(cx *evalCtx) bool {
		return cx.e.Type == collector.EventOpen && cx.e.Arg1&oTRUNC != 0
	},
}

// fieldAny resolves a field name to its value for detail rendering. Returns
// (value, true) when name is a known field, (nil, false) otherwise (so callers
// can fall back to treating the token as a literal string).
func fieldAny(cx *evalCtx, name string) (any, bool) {
	if f, ok := strFields[name]; ok {
		return f(cx), true
	}
	if f, ok := intFields[name]; ok {
		return f(cx), true
	}
	if f, ok := boolFields[name]; ok {
		return f(cx), true
	}
	return nil, false
}

// ── Helpers used inside conditions ────────────────────────────────────────────

// reverseShellMatch reproduces the legacy reverse_shell rule exactly: literal
// signatures plus the curl/wget|sh download-and-execute pattern, case-insensitive.
func reverseShellMatch(cmd string) bool {
	cl := strings.ToLower(cmd)
	for _, sig := range reverseShellSigs {
		if strings.Contains(cl, sig) {
			return true
		}
	}
	if strings.Contains(cl, "curl ") || strings.Contains(cl, "wget ") {
		for _, p := range []string{"|sh", "| sh", "|bash", "| bash"} {
			if strings.Contains(cl, p) {
				return true
			}
		}
	}
	return false
}

var reverseShellSigs = []string{
	"/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "nc -c", "pty.spawn", "socket.socket",
}

// ── small pure helpers (local copies; no detector import) ─────────────────────

func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

func dirName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if i == 0 {
			return "/"
		}
		return path[:i]
	}
	return ""
}

// processName mirrors detector.processName: prefer the executed binary's basename
// for execve, else the comm.
func processName(e *collector.Event) string {
	if e.Type == collector.EventExecve && e.Filename != "" {
		return baseName(e.Filename)
	}
	return e.ProcessName
}

func typeName(t uint8) string {
	switch t {
	case collector.EventExecve:
		return "execve"
	case collector.EventOpen:
		return "open"
	case collector.EventConnect:
		return "connect"
	case collector.EventClone:
		return "clone"
	case collector.EventPtrace:
		return "ptrace"
	case collector.EventModule:
		return "init_module"
	case collector.EventBPF:
		return "bpf"
	default:
		return "unknown"
	}
}

func scopeName(s Scope) string {
	if s == ScopeHost {
		return alerterScopeHost
	}
	return alerterScopeContainer
}

// kept as plain strings to avoid importing alerter consts here twice
const (
	alerterScopeHost      = "host"
	alerterScopeContainer = "container"
)
