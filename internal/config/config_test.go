package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearEnv blanks every KW_* variable for the duration of the test so a default
// case is not polluted by the developer's shell or a leaked .env. An empty value
// is treated as unset by every config helper (envOr/envInt/envBool/splitCSV).
// t.Setenv registers cleanup, restoring the prior value automatically.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(key, "KW_") {
			t.Setenv(key, "")
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with a clean env should succeed, got: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ServerName", cfg.ServerName, "kernelwatch-host"},
		{"Mode", cfg.Mode, "alert"},
		{"AncestryDepth", cfg.AncestryDepth, 5},
		{"AlertMinSeverity", cfg.AlertMinSeverity, "medium"},
		{"AlertMaxRate", cfg.AlertMaxRate, 10},
		{"AlertRateWindow", cfg.AlertRateWindow, 60},
		{"AlertFormat", cfg.AlertFormat, "native"},
		{"CorrelationEnabled", cfg.CorrelationEnabled, true},
		{"CorrelationWindow", cfg.CorrelationWindow, 300},
		{"CorrelationMinStages", cfg.CorrelationMinStages, 3},
		{"CorrelationMinScore", cfg.CorrelationMinScore, 120},
		{"CorrelationCooldown", cfg.CorrelationCooldown, 300},
		{"MonitorHost", cfg.MonitorHost, false},
		{"AuthLogEnabled", cfg.AuthLogEnabled, false},
		{"AuthLogPath", cfg.AuthLogPath, "/var/log/auth.log"},
		{"SSHBruteThreshold", cfg.SSHBruteThreshold, 5},
		{"SSHBruteWindow", cfg.SSHBruteWindow, 60},
		{"LogEnabled", cfg.LogEnabled, true},
		{"LogPath", cfg.LogPath, "/var/log/kernelwatch/alerts.json"},
		{"APIEnabled", cfg.APIEnabled, false},
		{"APIBindAddr", cfg.APIBindAddr, "127.0.0.1"},
		{"APIPort", cfg.APIPort, 8080},
		{"EBPFRingbufSize", cfg.EBPFRingbufSize, 16 * 1024 * 1024},
		{"DBEnabled", cfg.DBEnabled, false},
		{"DBRetentionDays", cfg.DBRetentionDays, 90},
		{"DBHost", cfg.DBHost, "localhost"},
		{"DBPort", cfg.DBPort, 5432},
		{"DBName", cfg.DBName, "kernelwatch"},
		{"DBUser", cfg.DBUser, "kernelwatch"},
		{"DBSSLMode", cfg.DBSSLMode, "disable"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadCoercion(t *testing.T) {
	clearEnv(t)

	t.Setenv("KW_SERVER_NAME", "host-7")
	t.Setenv("KW_ANCESTRY_DEPTH", "9")
	t.Setenv("KW_TRUSTED_PARENTS", " runner , , worker ") // trimmed, empties dropped
	t.Setenv("KW_MONITOR_HOST", "1")                      // ParseBool truthy
	t.Setenv("KW_CORRELATION_ENABLED", "false")
	t.Setenv("KW_ALERT_MAX_RATE", "not-a-number") // unparseable int falls back

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}

	if cfg.ServerName != "host-7" {
		t.Errorf("ServerName = %q, want host-7", cfg.ServerName)
	}
	if cfg.AncestryDepth != 9 {
		t.Errorf("AncestryDepth = %d, want 9", cfg.AncestryDepth)
	}
	if got := cfg.TrustedParents; len(got) != 2 || got[0] != "runner" || got[1] != "worker" {
		t.Errorf("TrustedParents = %#v, want [runner worker]", got)
	}
	if !cfg.MonitorHost {
		t.Errorf("MonitorHost = false, want true (KW_MONITOR_HOST=1)")
	}
	if cfg.CorrelationEnabled {
		t.Errorf("CorrelationEnabled = true, want false")
	}
	if cfg.AlertMaxRate != 10 {
		t.Errorf("AlertMaxRate = %d, want 10 (fallback on unparseable int)", cfg.AlertMaxRate)
	}
}

func TestLoadValidate(t *testing.T) {
	// A file and a directory used by the rules-path cases.
	dir := t.TempDir()
	file := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(file, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"defaults ok", nil, false},
		{"bad severity", map[string]string{"KW_ALERT_MIN_SEVERITY": "extreme"}, true},
		{"bad mode", map[string]string{"KW_MODE": "silent"}, true},
		{"bad alert format", map[string]string{"KW_ALERT_FORMAT": "json"}, true},
		{"db enabled no password", map[string]string{"KW_DB_ENABLED": "true"}, true},
		{"db enabled changeme", map[string]string{"KW_DB_ENABLED": "true", "KW_DB_PASSWORD": "changeme"}, true},
		{"db enabled good password", map[string]string{"KW_DB_ENABLED": "true", "KW_DB_PASSWORD": "s3cret-pw"}, false},
		{"api port too high", map[string]string{"KW_API_PORT": "70000"}, true},
		{"api enabled no token", map[string]string{"KW_API_ENABLED": "true"}, true},
		{"api enabled short token", map[string]string{"KW_API_ENABLED": "true", "KW_API_TOKEN": "short"}, true},
		{"api enabled changeme token", map[string]string{"KW_API_ENABLED": "true", "KW_API_TOKEN": "changeme-changeme-x"}, true},
		{"api enabled good token", map[string]string{"KW_API_ENABLED": "true", "KW_API_TOKEN": "0123456789abcdef0123"}, false},
		{"rules file missing", map[string]string{"KW_RULES_FILE": filepath.Join(dir, "nope.yaml")}, true},
		{"rules file is dir", map[string]string{"KW_RULES_FILE": dir}, true},
		{"rules file ok", map[string]string{"KW_RULES_FILE": file}, false},
		{"rules dir is file", map[string]string{"KW_RULES_DIR": file}, true},
		{"rules dir ok", map[string]string{"KW_RULES_DIR": dir}, false},
		{"webhook no url", map[string]string{"KW_WEBHOOK_ENABLED": "true"}, true},
		{"slack no url", map[string]string{"KW_SLACK_ENABLED": "true"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if tc.wantErr && err == nil {
				t.Errorf("Load() = nil error, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Load() = %v, want nil error", err)
			}
		})
	}
}

func TestIsMonitored(t *testing.T) {
	cfg := &Config{
		ContainerWhitelist: []string{"web", "api"},
		ContainerBlacklist: []string{"web"}, // blacklist wins even over whitelist
	}
	cases := []struct {
		name string
		want bool
	}{
		{"web", false},  // blacklisted, despite being whitelisted
		{"WEB", false},  // case-insensitive
		{"api", true},   // whitelisted
		{"API", true},   // case-insensitive
		{"other", false}, // not in non-empty whitelist
	}
	for _, c := range cases {
		if got := cfg.IsMonitored(c.name); got != c.want {
			t.Errorf("IsMonitored(%q) = %v, want %v", c.name, got, c.want)
		}
	}

	// With no whitelist, everything not blacklisted is monitored.
	open := &Config{ContainerBlacklist: []string{"noisy"}}
	if !open.IsMonitored("anything") {
		t.Errorf("IsMonitored with empty whitelist should monitor non-blacklisted containers")
	}
	if open.IsMonitored("noisy") {
		t.Errorf("IsMonitored should skip blacklisted container")
	}
}

func TestDSN(t *testing.T) {
	cfg := &Config{
		DBHost: "db", DBPort: 6543, DBName: "kw", DBUser: "u", DBPassword: "p", DBSSLMode: "require",
	}
	want := "host=db port=6543 dbname=kw user=u password=p sslmode=require"
	if got := cfg.DSN(); got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}
