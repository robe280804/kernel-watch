// Package logtail provides an SSH brute-force detector that tails the host auth
// log. eBPF can see the connect/execve of sshd but NOT the authentication
// outcome (success vs failure) — that lives only in the log — so a small log
// tailer is the right tool for credential-stuffing detection (T1110.001).
//
// It synthesizes host-scope "ssh_bruteforce" alerts into the same alert pipeline
// as the eBPF findings, so they are correlated, persisted, and shipped to the
// SIEM identically.
package logtail

import (
	"regexp"
	"sync"
	"time"
)

// failedAuthPatterns match a failed SSH authentication line across the common
// sshd/PAM phrasings, capturing the source IP in group 1.
var failedAuthPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Failed password for .*from (\d{1,3}(?:\.\d{1,3}){3})`),
	regexp.MustCompile(`Invalid user .*from (\d{1,3}(?:\.\d{1,3}){3})`),
	regexp.MustCompile(`Failed publickey for .*from (\d{1,3}(?:\.\d{1,3}){3})`),
	regexp.MustCompile(`authentication failure;.*rhost=(\d{1,3}(?:\.\d{1,3}){3})`),
	regexp.MustCompile(`Connection (?:closed|reset) by authenticating user .* (\d{1,3}(?:\.\d{1,3}){3})`),
	// IPv6 (best-effort): capture the bracketed/bare hextet form after "from".
	regexp.MustCompile(`Failed password for .*from ([0-9a-fA-F:]{3,}:[0-9a-fA-F:]+)`),
}

// FailedAuthIP returns the source IP of a failed-auth log line and whether the
// line matched. Pure function — the unit of the parser that tests exercise.
func FailedAuthIP(line string) (string, bool) {
	for _, re := range failedAuthPatterns {
		if m := re.FindStringSubmatch(line); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// tracker is a per-source-IP sliding-window counter. Add returns true exactly
// once each time an IP crosses the threshold within the window; after firing it
// resets that IP's window so a sustained attack alerts once per window rather
// than on every subsequent line.
type tracker struct {
	threshold int
	window    time.Duration

	mu  sync.Mutex
	hit map[string][]time.Time
}

func newTracker(threshold int, window time.Duration) *tracker {
	if threshold <= 0 {
		threshold = 5
	}
	if window <= 0 {
		window = time.Minute
	}
	return &tracker{threshold: threshold, window: window, hit: map[string][]time.Time{}}
}

// add records a failed attempt from ip at time now and returns (attempts, true)
// when this attempt crosses the threshold, otherwise (count, false).
func (t *tracker) add(ip string, now time.Time) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := now.Add(-t.window)
	ts := t.hit[ip]
	fresh := ts[:0]
	for _, at := range ts {
		if at.After(cutoff) {
			fresh = append(fresh, at)
		}
	}
	fresh = append(fresh, now)

	if len(fresh) >= t.threshold {
		// Fire and reset this IP's window (alert once per window, not per line).
		delete(t.hit, ip)
		return len(fresh), true
	}
	t.hit[ip] = fresh
	return len(fresh), false
}
