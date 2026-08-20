package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// collectRun drains a whole run and returns its samples plus the warnings it
// emitted, so error handling can be asserted end to end.
func collectRun(t *testing.T, cfg Config) ([]Sample, []string) {
	t.Helper()
	var warns []string
	r := NewRunner(cfg, func(m string) { warns = append(warns, m) })
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	ch := make(chan Sample, 64)
	go func() {
		defer close(ch)
		_ = r.Run(context.Background(), ch)
	}()
	var samples []Sample
	for s := range ch {
		samples = append(samples, s)
	}
	return samples, warns
}

// TestTimeoutIsRecordedNotFatal checks a slow server: the request fails, but
// total is still recorded and the run continues (PLAN §1.1, §4.4).
func TestTimeoutIsRecordedNotFatal(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	srv := newCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}), false)

	cfg := testConfig(t, srv.URL)
	cfg.Timeout = 150 * time.Millisecond
	cfg.Mode = ColdOnly

	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	s := c.probe(ctx, 1, 1)
	if s.Err == nil {
		t.Fatal("slow server produced no error, want a timeout")
	}
	if got := Classify(s.Err); got != ErrTimeout {
		t.Errorf("classified as %v (%q), want a timeout", got, Reason(s.Err))
	}
	if !s.Total.OK {
		t.Error("total not recorded: a failed request must still report how long it waited")
	}
	if !s.DNS.OK {
		t.Error("dns not recorded although the lookup completed before the timeout")
	}
	if s.Srv.OK {
		t.Error("srv measured although no response byte ever arrived")
	}
}

// TestConnectionRefusedIsClassified uses a port nothing listens on.
func TestConnectionRefusedIsClassified(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // the port is now free, so connecting must be refused

	u, _ := url.Parse("https://" + addr + "/")
	cfg := testConfig(t, u.String())
	cfg.Timeout = 2 * time.Second

	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, "https://"+addr))
	s := c.probe(context.Background(), 1, 1)
	if s.Err == nil {
		t.Fatal("connecting to a closed port succeeded")
	}
	if kind := Classify(s.Err); kind != ErrRefused && kind != ErrTimeout && kind != ErrReset {
		t.Errorf("classified as %q, want a connection failure", Reason(s.Err))
	}
	if s.TLS.OK {
		t.Error("tls measured although the TCP connection never came up")
	}
}

// TestCertificateFailureIsClassified checks that a verification failure is
// reported as a certificate problem rather than a generic error (PLAN §2.3).
func TestCertificateFailureIsClassified(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)

	cfg := testConfig(t, srv.URL)
	cfg.Insecure = false // do not trust httptest's self-signed certificate

	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	s := c.probe(context.Background(), 1, 1)
	if s.Err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	if !strings.HasPrefix(Reason(s.Err), "TLS:") {
		t.Errorf("reason = %q, want a TLS certificate reason", Reason(s.Err))
	}
	// The handshake was reached and failed, and how long that took is the
	// diagnostic value.
	if !s.TLS.OK {
		t.Error("time spent on the failed handshake was discarded")
	}
	if !s.TCP.OK {
		t.Error("tcp not measured although the connection was established")
	}
}

// TestConsecutiveFailuresStopTheRun covers the safety valve (PLAN §4.5).
func TestConsecutiveFailuresStopTheRun(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	u, _ := url.Parse(srv.URL)

	cfg := testConfig(t, srv.URL)
	cfg.Count = 20
	cfg.Mode = ColdOnly
	cfg.MaxFails = 3
	cfg.Interval = time.Millisecond
	cfg.Timeout = 2 * time.Second

	var warns []string
	r := NewRunner(cfg, func(m string) { warns = append(warns, m) })
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	// Take the server away, so every round from now on fails.
	srv.Close()
	_ = u

	ch := make(chan Sample, 64)
	go func() {
		defer close(ch)
		_ = r.Run(context.Background(), ch)
	}()
	n := 0
	for range ch {
		n++
	}

	if n > cfg.MaxFails {
		t.Errorf("ran %d rounds against a dead server, want at most %d", n, cfg.MaxFails)
	}
	if !strings.Contains(strings.Join(warns, " "), "consecutive failures") {
		t.Errorf("no warning explaining the early stop, got %v", warns)
	}
}

// TestOneFailingModeDoesNotSinkTheOther is the per-mode independence rule: warm
// keeps producing usable samples while cold fails (PLAN §2.3, §4.4).
func TestOneFailingModeDoesNotSinkTheOther(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	cfg := testConfig(t, srv.URL)
	cfg.Count = 2
	cfg.Warmup = 0
	cfg.Interval = time.Millisecond

	r := NewRunner(cfg, nil)
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	// Break only the cold path: its resolver now points at a name that cannot
	// resolve, while warm keeps using the connection it already holds.
	r.cold.rs = &resolver{r: &net.Resolver{}, network: "ip"}
	r.cold.cfg.URL = mustURL(t, "https://tlsping-invalid.invalid/")

	ch := make(chan Sample, 32)
	go func() {
		defer close(ch)
		_ = r.Run(context.Background(), ch)
	}()

	var coldFails, warmOK int
	for s := range ch {
		switch {
		case s.Mode == Cold && s.Err != nil:
			coldFails++
		case s.Mode == Warm && s.Err == nil:
			warmOK++
		}
	}
	if coldFails == 0 {
		t.Fatal("cold was expected to fail")
	}
	if warmOK == 0 {
		t.Error("warm produced nothing usable although only the cold path was broken")
	}
}

// TestRetryAfterOn503Stops covers the second politeness trigger (PLAN §4.5).
func TestRetryAfterOn503Stops(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusServiceUnavailable)
	}), false)

	cfg := testConfig(t, srv.URL)
	cfg.Count = 10
	cfg.Mode = ColdOnly
	cfg.Interval = time.Millisecond

	samples, warns := collectRun(t, cfg)
	if len(samples) != 1 {
		t.Fatalf("got %d samples, want 1: a 503 with Retry-After stops the run", len(samples))
	}
	if !samples[0].Responded() {
		t.Error("503 counted as a failure; it is a response, so it is a success (PLAN §4.4)")
	}
	if !strings.Contains(strings.Join(warns, " "), "503") {
		t.Errorf("no warning naming the trigger, got %v", warns)
	}
}

// TestErrorStatusesAreSuccesses: 4xx and 5xx are valid latency measurements.
func TestErrorStatusesAreSuccesses(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), false)

	cfg := testConfig(t, srv.URL)
	cfg.Count = 2
	cfg.Warmup = 0
	cfg.Interval = time.Millisecond

	samples, _ := collectRun(t, cfg)
	for _, s := range samples {
		if !s.Responded() {
			t.Errorf("%s round %d treated 404 as a failure: %v", s.Mode, s.Round, s.Err)
		}
		if s.Status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", s.Status)
		}
		if !s.Total.OK {
			t.Error("total missing on a 404, but the round trip is still a valid measurement")
		}
	}
}

// TestHTTP2Negotiation checks the protocol allow-list actually takes effect and
// is verified against the response (PLAN §4.6).
func TestHTTP2Negotiation(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), true)

	t.Run("http2 requested", func(t *testing.T) {
		cfg := testConfig(t, srv.URL)
		cfg.HTTPVersion = "2"
		c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
		s := c.probe(context.Background(), 1, 1)
		if s.Err != nil {
			t.Fatalf("probe: %v", s.Err)
		}
		if s.Proto != "h2" {
			t.Errorf("proto = %q, want h2", s.Proto)
		}
		if s.ALPN != "h2" {
			t.Errorf("alpn = %q, want h2", s.ALPN)
		}
	})

	t.Run("http1.1 forced", func(t *testing.T) {
		cfg := testConfig(t, srv.URL)
		cfg.HTTPVersion = "1.1"
		c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
		s := c.probe(context.Background(), 1, 1)
		if s.Err != nil {
			t.Fatalf("probe: %v", s.Err)
		}
		if s.Proto != "http/1.1" {
			t.Errorf("proto = %q, want http/1.1 even though the server offers h2", s.Proto)
		}
	})
}

// TestTLSSessionResumptionShowsUpInCold is the effect PLAN §1.2 predicts: the
// tls phase drops once a session ticket can be reused.
func TestTLSSessionResumptionShowsUpInCold(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	srv.TLS = &tls.Config{} //nolint:gosec // already started; only read below

	cfg := testConfig(t, srv.URL)
	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))

	first := c.probe(context.Background(), 1, 1)
	if first.Err != nil {
		t.Fatalf("first cold probe: %v", first.Err)
	}
	if first.Resumed {
		t.Error("the first handshake reported resumption, but there was no earlier session")
	}

	second := c.probe(context.Background(), 2, 2)
	if second.Err != nil {
		t.Fatalf("second cold probe: %v", second.Err)
	}
	// The server must offer tickets for this to hold; Go's test server does.
	if !second.Resumed {
		t.Error("the second cold handshake did not resume, so the shared session cache is not in effect")
	}
	if got := srv.count(); got != 2 {
		t.Errorf("server saw %d connections, want 2: resumption must not turn cold into warm", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
