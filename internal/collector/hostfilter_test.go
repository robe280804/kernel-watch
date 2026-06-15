package collector

import (
	"os"
	"testing"

	"kernelwatch/internal/config"
)

func TestHostFilterKeep(t *testing.T) {
	hf := newHostFilter(&config.Config{
		HostExecExclude: []string{"node_exporter"},
	})
	const otherPID = 4242 // not us

	cases := []struct {
		name string
		e    Event
		keep bool
	}{
		{"watched open passes", Event{PID: otherPID, Type: EventOpen, Filename: "/etc/cron.d/x"}, true},
		{"unwatched open dropped", Event{PID: otherPID, Type: EventOpen, Filename: "/usr/lib/x.so"}, false},
		{"authorized_keys substring passes", Event{PID: otherPID, Type: EventOpen, Filename: "/home/u/.ssh/authorized_keys"}, true},
		{"connect dropped", Event{PID: otherPID, Type: EventConnect}, false},
		{"clone dropped", Event{PID: otherPID, Type: EventClone}, false},
		{"execve kept", Event{PID: otherPID, Type: EventExecve, Filename: "/bin/bash", ProcessName: "bash"}, true},
		{"excluded agent dropped", Event{PID: otherPID, Type: EventExecve, ProcessName: "node_exporter"}, false},
		{"module kept", Event{PID: otherPID, Type: EventModule}, true},
		{"self pid dropped", Event{PID: uint32(os.Getpid()), Type: EventExecve, ProcessName: "bash"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.e
			if got := hf.keep(&e); got != tc.keep {
				t.Fatalf("keep(%s) = %v, want %v", tc.name, got, tc.keep)
			}
		})
	}
}

func TestHostFilterOpenExtra(t *testing.T) {
	hf := newHostFilter(&config.Config{HostOpenWatchExtra: []string{"/opt/app/secrets"}})
	e := Event{PID: 4242, Type: EventOpen, Filename: "/opt/app/secrets/token"}
	if !hf.keep(&e) {
		t.Fatal("operator-configured extra open path should pass the host filter")
	}
}

func TestHostOpenWatched(t *testing.T) {
	for _, p := range []string{"/etc/sudoers.d/x", "/var/log/auth.log", "/var/run/docker.sock", "/root/.ssh/authorized_keys"} {
		if !HostOpenWatched(p) {
			t.Fatalf("%q should be watched", p)
		}
	}
	if HostOpenWatched("/usr/share/zoneinfo/UTC") {
		t.Fatal("unrelated path should not be watched")
	}
}
