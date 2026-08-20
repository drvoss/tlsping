package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingServer is a TLS test server that reports how many distinct
// connections it accepted. The connection count is the invariant the whole tool
// rests on (PLAN §7).
type countingServer struct {
	*httptest.Server
	mu    sync.Mutex
	conns int
}

func newCountingServer(t *testing.T, h http.Handler, http2 bool) *countingServer {
	t.Helper()
	cs := &countingServer{}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			cs.mu.Lock()
			cs.conns++
			cs.mu.Unlock()
		}
	}
	srv.EnableHTTP2 = http2
	srv.StartTLS()
	cs.Server = srv
	t.Cleanup(srv.Close)
	return cs
}

func (cs *countingServer) count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.conns
}

func testConfig(t *testing.T, rawURL string) Config {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return Config{
		URL:         u,
		Headers:     http.Header{},
		UA:          "tlsping-test",
		Count:       4,
		Interval:    time.Millisecond,
		Timeout:     5 * time.Second,
		Mode:        Both,
		Order:       "alternate",
		HTTPVersion: "auto",
		PinIP:       true,
		Insecure:    true,
		MaxBody:     DefaultMaxBody,
		MaxFails:    3,
	}
}

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// TestColdOpensOneConnectionPerProbe is the primary regression test: N cold
// probes must cost the server exactly N connections (PLAN §7).
func TestColdOpensOneConnectionPerProbe(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	cfg := testConfig(t, srv.URL)

	const n = 5
	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	for i := 1; i <= n; i++ {
		s := c.probe(context.Background(), i, i)
		if s.Err != nil {
			t.Fatalf("cold probe %d: %v", i, s.Err)
		}
		if s.Status != http.StatusOK {
			t.Fatalf("cold probe %d: status %d", i, s.Status)
		}
	}
	if got := srv.count(); got != n {
		t.Fatalf("cold probes opened %d connections, want %d", got, n)
	}
}

// TestWarmReusesOneConnection is the mirror invariant: N warm probes must cost
// the server exactly one connection, and every probe after the first must
// report Reused (PLAN §7).
func TestWarmReusesOneConnection(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	cfg := testConfig(t, srv.URL)

	const n = 5
	w := newWarmRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	defer w.close()

	for i := 1; i <= n; i++ {
		s := w.probe(context.Background(), i, i)
		if s.Err != nil {
			t.Fatalf("warm probe %d: %v", i, s.Err)
		}
		switch {
		case i == 1 && s.Reused:
			t.Fatal("first warm probe reported Reused, but the shared Transport had no connection yet")
		case i > 1 && !s.Reused:
			t.Fatalf("warm probe %d did not reuse the connection", i)
		}
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("warm probes opened %d connections, want 1", got)
	}
}

// TestWarmGivesUpReuseOnOversizedBody covers the path codex flagged: a body
// past the cap cannot be drained, so HTTP/1.x cannot reuse the connection and
// every later warm probe must dial again (PLAN §4.2).
func TestWarmGivesUpReuseOnOversizedBody(t *testing.T) {
	const limit = 1024
	body := make([]byte, limit*4)
	srv := newCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}), false)

	cfg := testConfig(t, srv.URL)
	cfg.MaxBody = limit

	w := newWarmRunner(cfg, http.MethodGet, mustAddr(t, srv.URL))
	defer w.close()

	const n = 3
	for i := 1; i <= n; i++ {
		s := w.probe(context.Background(), i, i)
		if s.Err != nil {
			t.Fatalf("warm probe %d: %v", i, s.Err)
		}
		if !s.Overflow {
			t.Fatalf("warm probe %d: Overflow not flagged for a %d-byte body over a %d cap", i, len(body), limit)
		}
		if s.Reused {
			t.Fatalf("warm probe %d reported Reused, but the previous body was never drained", i)
		}
	}
	if got := srv.count(); got != n {
		t.Fatalf("server saw %d connections, want %d: an undrained body must force a redial", got, n)
	}
}

// TestColdPhasesAreNonOverlapping checks the mode-specific decomposition:
// cold records dns/tcp/tls and must leave wait unmeasured, warm the reverse
// (PLAN §1.1).
func TestColdPhasesAreNonOverlapping(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	cfg := testConfig(t, srv.URL)

	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	cold := c.probe(context.Background(), 1, 1)
	if cold.Err != nil {
		t.Fatalf("cold: %v", cold.Err)
	}
	for name, p := range map[string]Phase{"dns": cold.DNS, "tcp": cold.TCP, "tls": cold.TLS, "srv": cold.Srv, "total": cold.Total} {
		if !p.OK {
			t.Errorf("cold %s not measured", name)
		}
	}
	if cold.Wait.OK {
		t.Error("cold recorded wait, which double-counts tcp+tls")
	}
	if sum, ok := cold.PhaseSum(); ok && cold.Total.D < sum {
		t.Errorf("cold total %v < phase sum %v", cold.Total.D, sum)
	}
	if !cold.Other.OK || cold.Other.D < 0 {
		t.Errorf("cold other = %v (OK=%v), want a non-negative measured value", cold.Other.D, cold.Other.OK)
	}

	w := newWarmRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	defer w.close()
	warm := w.probe(context.Background(), 1, 2)
	if warm.Err != nil {
		t.Fatalf("warm: %v", warm.Err)
	}
	if !warm.Wait.OK || !warm.Srv.OK || !warm.Total.OK {
		t.Error("warm must measure wait, srv and total")
	}
	if warm.DNS.OK || warm.TCP.OK || warm.TLS.OK {
		t.Error("warm must not record dns/tcp/tls: it pays for none of them")
	}
	if !warm.Other.OK || warm.Other.D < 0 {
		t.Errorf("warm other = %v (OK=%v), want a non-negative measured value", warm.Other.D, warm.Other.OK)
	}
}

// TestPinnedDialKeepsTLSWorking verifies that pinning rewrites only the dial
// target: the URL host stays intact for SNI and verification (PLAN §4.2).
func TestPinnedDialKeepsTLSWorking(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)

	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	// httptest's certificate is issued for example.com, so addressing the server
	// by that name proves SNI and verification still use the URL host while the
	// dial goes to the pinned loopback address.
	cfg := testConfig(t, "https://example.com:"+port+"/")
	cfg.Insecure = false
	cfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	c := newColdRunner(cfg, http.MethodHead, mustAddr(t, srv.URL))
	s := c.probe(context.Background(), 1, 1)
	if s.Err != nil {
		t.Fatalf("pinned dial with hostname failed: %v", s.Err)
	}
	if !strings.HasPrefix(s.Addr, "127.0.0.1:") {
		t.Fatalf("dialed %q, want the pinned 127.0.0.1 address", s.Addr)
	}
	if s.TLSVer == "" {
		t.Fatal("no TLS version recorded")
	}
}

// TestHooksAreRaceFree exercises the collector from an HTTP/2 server, where
// hooks may fire concurrently (PLAN §4.1). Meaningful under -race.
func TestHooksAreRaceFree(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), true)
	cfg := testConfig(t, srv.URL)

	w := newWarmRunner(cfg, http.MethodGet, mustAddr(t, srv.URL))
	defer w.close()
	// Prime the connection so the parallel probes multiplex over it.
	if s := w.probe(context.Background(), 0, 0); s.Err != nil {
		t.Fatalf("prime: %v", s.Err)
	}

	var wg sync.WaitGroup
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if s := w.probe(context.Background(), i, i); s.Err != nil {
				t.Errorf("concurrent probe %d: %v", i, s.Err)
			}
		}(i)
	}
	wg.Wait()
}

// TestPreflightDetectsHeadRejection covers the HEAD->GET fallback happening
// before measurement starts, not inside a round (PLAN §4.2).
func TestPreflightDetectsHeadRejection(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), false)

	cfg := testConfig(t, srv.URL)
	r := NewRunner(cfg, nil)
	info, err := r.Preflight(context.Background())
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer r.Close()
	if info.Method != http.MethodGet {
		t.Fatalf("preflight settled on %s, want GET after a 405 on HEAD", info.Method)
	}
	if info.Addr == "" || info.Proto == "" {
		t.Fatalf("preflight left RunInfo incomplete: %+v", info)
	}
}

// TestRunnerAlternatesOrder checks that the round order flips, which is what
// makes the cold/warm comparison paired rather than order-biased (PLAN §4.3).
func TestRunnerAlternatesOrder(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	cfg := testConfig(t, srv.URL)
	cfg.Count = 4
	cfg.Warmup = 0

	r := NewRunner(cfg, nil)
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	ch := make(chan Sample, 16)
	go func() {
		_ = r.Run(context.Background(), ch)
		close(ch)
	}()

	var order []string
	for s := range ch {
		order = append(order, s.Mode.String())
	}
	want := []string{"cold", "warm", "warm", "cold", "cold", "warm", "warm", "cold"}
	if len(order) != len(want) {
		t.Fatalf("got %d samples (%v), want %d", len(order), order, len(want))
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("sample order = %v, want %v", order, want)
		}
	}
}

// TestRunnerStopsOn429 covers the politeness trigger (PLAN §4.5).
func TestRunnerStopsOn429(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}), false)

	cfg := testConfig(t, srv.URL)
	cfg.Count = 10
	cfg.Mode = ColdOnly

	var warns []string
	r := NewRunner(cfg, func(m string) { warns = append(warns, m) })
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	ch := make(chan Sample, 32)
	go func() {
		_ = r.Run(context.Background(), ch)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	if n != 1 {
		t.Fatalf("got %d samples, want 1: the run must stop on the first 429", n)
	}
	if len(warns) == 0 || !strings.Contains(strings.Join(warns, " "), "429") {
		t.Fatalf("no 429 warning emitted, got %v", warns)
	}
}

// TestRunEmitsEverythingOnCancel guards the M3 requirement that an interrupt
// loses no collected sample (PLAN §6).
func TestRunEmitsEverythingOnCancel(t *testing.T) {
	srv := newCountingServer(t, http.HandlerFunc(okHandler), false)
	cfg := testConfig(t, srv.URL)
	cfg.Count = 0 // unbounded
	cfg.Interval = 20 * time.Millisecond
	cfg.Mode = ColdOnly

	r := NewRunner(cfg, nil)
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan Sample) // unbuffered: a dropped sample would deadlock
	done := make(chan struct{})
	go func() {
		_ = r.Run(ctx, ch)
		close(ch)
		close(done)
	}()

	got := 0
	for range ch {
		got++
		if got == 3 {
			cancel()
		}
	}
	<-done
	if got < 3 {
		t.Fatalf("received %d samples before cancel, want at least 3", got)
	}
}

func mustAddr(t *testing.T, rawURL string) netip.Addr {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split %q: %v", u.Host, err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("parse addr %q: %v", host, err)
	}
	return a
}
