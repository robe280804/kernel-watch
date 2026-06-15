package logtail

import (
	"testing"
	"time"

	"kernelwatch/internal/alerter"
)

func TestFailedAuthIP(t *testing.T) {
	cases := []struct {
		line string
		ip   string
		ok   bool
	}{
		{"Jan  2 10:00:00 h sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2", "203.0.113.7", true},
		{"Jan  2 10:00:00 h sshd[1]: Failed password for invalid user admin from 198.51.100.3 port 40", "198.51.100.3", true},
		{"Jan  2 10:00:00 h sshd[1]: Invalid user oracle from 192.0.2.55", "192.0.2.55", true},
		{"Jan  2 10:00:00 h sshd[1]: Accepted password for deploy from 10.0.0.2 port 22 ssh2", "", false},
		{"random log line", "", false},
	}
	for _, c := range cases {
		ip, ok := FailedAuthIP(c.line)
		if ok != c.ok || ip != c.ip {
			t.Fatalf("FailedAuthIP(%q) = (%q,%v), want (%q,%v)", c.line, ip, ok, c.ip, c.ok)
		}
	}
}

func TestTrackerSlidingWindow(t *testing.T) {
	tr := newTracker(3, time.Minute)
	base := time.Unix(1700000000, 0)

	// Two attempts: below threshold.
	if _, fired := tr.add("1.2.3.4", base); fired {
		t.Fatal("first attempt should not fire")
	}
	if _, fired := tr.add("1.2.3.4", base.Add(time.Second)); fired {
		t.Fatal("second attempt should not fire")
	}
	// Third within window: fires.
	if n, fired := tr.add("1.2.3.4", base.Add(2*time.Second)); !fired || n != 3 {
		t.Fatalf("third attempt should fire at 3, got (%d,%v)", n, fired)
	}
	// Window resets after firing — a single later attempt does not re-fire.
	if _, fired := tr.add("1.2.3.4", base.Add(3*time.Second)); fired {
		t.Fatal("should not re-fire immediately after reset")
	}

	// Attempts spread beyond the window never accumulate to the threshold.
	tr2 := newTracker(3, 10*time.Second)
	for i := 0; i < 5; i++ {
		if _, fired := tr2.add("9.9.9.9", base.Add(time.Duration(i)*30*time.Second)); fired {
			t.Fatalf("attempts outside the window must not fire (i=%d)", i)
		}
	}
}

func TestTailerSynthesizesHostAlert(t *testing.T) {
	tl := New(Config{Threshold: 2, Window: time.Minute, ServerName: "web-01"}, nil)
	now := time.Unix(1700000000, 0)
	line := "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"

	if a := tl.handleLine(line, now); a != nil {
		t.Fatal("first failure should not yet alert")
	}
	a := tl.handleLine(line, now.Add(time.Second))
	if a == nil {
		t.Fatal("threshold crossing should synthesize an alert")
	}
	if a.RuleID != "ssh_bruteforce" || a.Scope != alerter.ScopeHost || a.Severity != alerter.SeverityHigh {
		t.Fatalf("unexpected alert shape: %+v", a)
	}
	if a.Details["source_ip"] != "203.0.113.9" {
		t.Fatalf("source_ip missing/wrong: %+v", a.Details)
	}
}
