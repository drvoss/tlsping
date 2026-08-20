package cli

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/drvoss/tlsping/internal/probe"
)

func parse(t *testing.T, args ...string) (*Config, error) {
	t.Helper()
	return Parse(args, "0.1.0", io.Discard)
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"google.com", "https://google.com/"},
		{"https://google.com", "https://google.com/"},
		{"http://example.org/x", "http://example.org/x"},
		{"https://example.org:8443/a?b=c", "https://example.org:8443/a?b=c"},
		{"example.com:8443", "https://example.com:8443/"},
		{"[2606:4700::1111]", "https://[2606:4700::1111]/"},
	}
	for _, c := range cases {
		cfg, err := parse(t, c.in)
		if err != nil {
			t.Errorf("parse %q: %v", c.in, err)
			continue
		}
		if got := cfg.URL.String(); got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRejectsBadTargets(t *testing.T) {
	for _, in := range []string{
		"ftp://example.com",
		"https://",
		"https://user:password@example.com",
		"",
	} {
		if _, err := parse(t, in); err == nil {
			t.Errorf("parse %q succeeded, want an error", in)
		}
	}
	if _, err := parse(t); err == nil {
		t.Error("parse with no target succeeded, want an error")
	}
	if _, err := parse(t, "a.com", "b.com"); err == nil {
		t.Error("two targets accepted, but multi-host is out of scope for v1")
	}
}

func TestFlagCombinations(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"json and csv", []string{"--json", "--csv", "a.com"}, "mutually exclusive"},
		{"quiet and verbose", []string{"-q", "-v", "a.com"}, "mutually exclusive"},
		{"v4 and v6", []string{"-4", "-6", "a.com"}, "mutually exclusive"},
		{"http/3", []string{"--http-version", "3", "a.com"}, "not supported"},
		{"bad http version", []string{"--http-version", "9", "a.com"}, "invalid"},
		{"bad mode", []string{"-m", "lukewarm", "a.com"}, "invalid"},
		{"bad order", []string{"--order", "random", "a.com"}, "invalid"},
		{"negative count", []string{"-n", "-1", "a.com"}, "invalid count"},
		{"negative warmup", []string{"--warmup", "-1", "a.com"}, "invalid --warmup"},
		{"zero timeout", []string{"-w", "0s", "a.com"}, "invalid --timeout"},
		{"malformed header", []string{"-H", "nocolon", "a.com"}, "Name: value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse(t, c.args...)
			if err == nil {
				t.Fatalf("args %v accepted, want an error containing %q", c.args, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, c.wantErr)
			}
		})
	}
}

func TestAliasesAgree(t *testing.T) {
	for _, args := range [][]string{
		{"-n", "3", "a.com"},
		{"-c", "3", "a.com"},
		{"--count", "3", "a.com"},
	} {
		cfg, err := parse(t, args...)
		if err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		if cfg.Count != 3 {
			t.Errorf("%v gave count %d, want 3", args, cfg.Count)
		}
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := parse(t, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Count != 10 {
		t.Errorf("count = %d, want 10", cfg.Count)
	}
	if cfg.Interval != time.Second {
		t.Errorf("interval = %v, want 1s", cfg.Interval)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", cfg.Timeout)
	}
	if cfg.Warmup != 1 {
		t.Errorf("warmup = %d, want 1", cfg.Warmup)
	}
	if cfg.Mode != probe.Both {
		t.Errorf("mode = %v, want both", cfg.Mode)
	}
	if cfg.Order != "alternate" {
		t.Errorf("order = %q, want alternate", cfg.Order)
	}
	if !cfg.PinIP {
		t.Error("IP pinning is off by default, but pinning is the default and --no-pin-ip opts out")
	}
	if cfg.Method != "" {
		t.Errorf("method = %q, want empty so the preflight can decide", cfg.Method)
	}
}

// TestIntervalFloorIsEnforced covers the politeness floor: it is clamped, not
// rejected, and the user is told (PLAN §4.5).
func TestIntervalFloorIsEnforced(t *testing.T) {
	cfg, err := parse(t, "-i", "1ms", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != MinInterval {
		t.Errorf("interval = %v, want it clamped to %v", cfg.Interval, MinInterval)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("the interval was clamped silently")
	}
}

func TestWarmupCoveringEveryRoundWarns(t *testing.T) {
	cfg, err := parse(t, "-n", "2", "--warmup", "2", "example.com")
	if err != nil {
		t.Fatalf("expected a warning, not an error: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("no warning although warmup excludes every round")
	}
}

func TestHeadersAccumulate(t *testing.T) {
	cfg, err := parse(t, "-H", "X-A: 1", "--header", "X-B: 2", "-H", "X-A: 3", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Headers.Values("X-A"); len(got) != 2 {
		t.Errorf("X-A = %v, want both values kept", got)
	}
	if got := cfg.Headers.Get("X-B"); got != "2" {
		t.Errorf("X-B = %q, want %q", got, "2")
	}
}

func TestHelpAndVersionAreNotErrors(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "--version"} {
		var sb strings.Builder
		_, err := Parse([]string{arg}, "0.1.0", &sb)
		if !errors.Is(err, ErrHelp) {
			t.Errorf("%s returned %v, want ErrHelp", arg, err)
		}
		if sb.Len() == 0 {
			t.Errorf("%s printed nothing", arg)
		}
	}
}

func TestProbeConfigCarriesEverything(t *testing.T) {
	cfg, err := parse(t, "-m", "warm", "--order", "warm-first", "-X", "get",
		"--cache-bust", "--no-pin-ip", "-6", "-k", "-n", "7", "-w", "2s", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Probe()
	if p.Mode != probe.WarmOnly {
		t.Errorf("mode = %v, want warm-only", p.Mode)
	}
	if p.Order != "warm-first" {
		t.Errorf("order = %q", p.Order)
	}
	if p.Method != "GET" {
		t.Errorf("method = %q, want it upper-cased to GET", p.Method)
	}
	if !p.CacheBust || p.PinIP || !p.Insecure {
		t.Errorf("flags lost: cacheBust=%v pinIP=%v insecure=%v", p.CacheBust, p.PinIP, p.Insecure)
	}
	if p.IPVersion != 6 {
		t.Errorf("ip version = %d, want 6", p.IPVersion)
	}
	if p.Count != 7 || p.Timeout != 2*time.Second {
		t.Errorf("count = %d, timeout = %v", p.Count, p.Timeout)
	}
	if !strings.HasPrefix(p.UA, "tlsping/") {
		t.Errorf("user agent = %q, want it to identify the tool", p.UA)
	}
	if p.MaxFails <= 0 {
		t.Error("consecutive-failure limit not set, so a dead server would be hammered")
	}
}
