package probe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Runner schedules rounds and emits samples on a channel. It never touches a
// renderer; main wires the two together (PLAN §5.1).
type Runner struct {
	cfg  Config
	warn func(string)

	method string
	pinned netip.Addr
	info   RunInfo

	cold *coldRunner
	warm *warmRunner

	seq int
}

// NewRunner builds a runner. Preflight must be called before Run.
func NewRunner(cfg Config, warn func(string)) *Runner {
	if warn == nil {
		warn = func(string) {}
	}
	return &Runner{cfg: cfg, warn: warn}
}

// Preflight sends exactly one request before measuring, to settle the method
// and to learn the things that only an established connection can tell us: the
// peer address, the negotiated protocol and the TLS version (PLAN §4.2).
//
// It runs on its own throwaway Transport and is excluded from statistics,
// warmup and the connection-count check.
func (r *Runner) Preflight(ctx context.Context) (RunInfo, error) {
	if r.method != "" {
		return RunInfo{}, errors.New("Preflight called twice")
	}
	host := r.cfg.URL.Hostname()

	rs := newResolver(r.cfg.ipNetwork())
	lookupCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	addrs, dnsDur, err := rs.lookup(lookupCtx, host)
	cancel()
	if err != nil {
		return RunInfo{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if r.cfg.PinIP {
		r.pinned = addrs[0]
		r.warnIfProxied()
	} else if r.cfg.Mode == Both {
		// Without pinning, cold follows each round's lookup while warm stays on
		// whichever address its one connection landed on. Behind round-robin
		// DNS or anycast the two modes can end up measuring different servers,
		// which is the comparison this tool exists to make (PLAN §4.2).
		r.warn("--no-pin-ip: cold and warm may reach different servers behind round-robin DNS or anycast")
	}

	method := r.cfg.Method
	detect := method == ""
	if detect {
		method = http.MethodHead
	}

	ex, err := r.preflightOnce(ctx, method)
	if err != nil {
		return RunInfo{}, err
	}
	// A server that rejects HEAD gets a ranged GET instead, decided here rather
	// than mid-round: a two-request round would break the connection-count
	// invariant in PLAN §7.
	if detect && (ex.status == http.StatusMethodNotAllowed || ex.status == http.StatusNotImplemented) {
		method = http.MethodGet
		ex, err = r.preflightOnce(ctx, method)
		if err != nil {
			return RunInfo{}, err
		}
	}
	r.method = method

	if loc := ex.header.Get("Location"); ex.status >= 300 && ex.status < 400 && loc != "" {
		r.warn(fmt.Sprintf("%d redirect to %s — redirects are not followed; re-run against the final URL", ex.status, loc))
	}
	if want := r.cfg.HTTPVersion; want == "2" && ex.proto != "h2" {
		r.warn("requested HTTP/2 but negotiated " + ex.proto)
	}

	addr := ex.res.remoteAddr
	if addr == "" {
		addr = hostPort(r.cfg.URL.Host, r.cfg.URL.Scheme)
	}

	r.info = RunInfo{
		URL:      r.cfg.URL.String(),
		Method:   method,
		Addr:     addr,
		Proto:    ex.proto,
		TLSVer:   ex.res.tlsVer,
		ALPN:     ex.res.alpn,
		Pinned:   r.cfg.PinIP,
		DNSFirst: Measured(dnsDur),
		Bytes:    ex.bytes,
		Count:    r.cfg.Count,
		Interval: r.cfg.Interval,
		Timeout:  r.cfg.Timeout,
		Order:    r.cfg.Order,
		Mode:     r.cfg.Mode,
		Host:     host,
		Warmup:   r.cfg.Warmup,
	}

	if r.cfg.Mode.HasCold() {
		r.cold = newColdRunner(r.cfg, method, r.pinned)
	}
	if r.cfg.Mode.HasWarm() {
		r.warm = newWarmRunner(r.cfg, method, r.pinned)
	}
	return r.info, nil
}

func (r *Runner) preflightOnce(ctx context.Context, method string) (exchange, error) {
	tr := newTransport(transportOpts{
		cfg:          r.cfg,
		pinned:       r.pinned,
		disableProxy: r.cfg.PinIP,
		keepAlive:    false,
	})
	defer tr.CloseIdleConnections()

	reqCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	req, err := buildRequest(reqCtx, r.cfg, method, 0)
	if err != nil {
		return exchange{}, err
	}
	client := &http.Client{Transport: tr, CheckRedirect: noFollow}
	ex := do(client, req, r.cfg.maxBody())
	if ex.err != nil {
		return exchange{}, fmt.Errorf("%s %s: %w", method, r.cfg.URL, ex.err)
	}
	return ex, nil
}

// warnIfProxied tells the user when pinning has silently disabled their proxy.
func (r *Runner) warnIfProxied() {
	req := &http.Request{URL: r.cfg.URL, Header: http.Header{}}
	if p, err := http.ProxyFromEnvironment(req); err == nil && p != nil {
		r.warn(fmt.Sprintf("proxy %s ignored: IP pinning bypasses it — use --no-pin-ip to measure through the proxy", p))
	}
}

// Close releases the shared warm Transport.
func (r *Runner) Close() {
	if r.warm != nil {
		r.warm.close()
	}
}

// Run executes rounds until the count is reached, the context is cancelled or
// a safety trigger fires. Every sample produced is sent on out before Run
// returns, so an interrupt loses nothing (PLAN §6 M3).
//
// The send is deliberately blocking rather than selecting on ctx.Done(): losing
// the sample that was in flight when the user pressed Ctrl+C would defeat the
// point. The caller therefore owns out and must drain it until Run returns.
func (r *Runner) Run(ctx context.Context, out chan<- Sample) error {
	if r.method == "" {
		return errors.New("Run called before Preflight")
	}
	defer r.Close()

	start := time.Now()
	consecutiveFails := 0
	warnedOther := false
	warnedOverflow := false

	for round := 1; r.cfg.Count == 0 || round <= r.cfg.Count; round++ {
		if ctx.Err() != nil {
			return nil
		}
		if round > 1 {
			// Schedule against the run start so the interval does not drift by
			// the duration of each round.
			target := start.Add(time.Duration(round-1) * r.cfg.Interval)
			if !sleepUntil(ctx, target) {
				return nil
			}
		}

		warmup := round <= r.cfg.Warmup
		modes := r.roundOrder(round)

		for i, mode := range modes {
			if ctx.Err() != nil {
				return nil
			}
			if i > 0 {
				// Sequential, never parallel: two connections would contend for
				// bandwidth and server queue and pollute each other (PLAN §4.3).
				if !sleepFor(ctx, r.cfg.Interval/4) {
					return nil
				}
			}

			s := r.probeOnce(ctx, mode, round)
			s.IsWarmup = warmup
			out <- s

			// A body over the cap cannot be drained, so HTTP/1.x cannot reuse
			// the connection and every later warm probe has to dial again. That
			// looks like a keep-alive failure unless we say why.
			if !warnedOverflow && s.Overflow {
				r.warn(fmt.Sprintf("response body exceeds the %d KiB cap — the connection cannot be reused, so warm will keep opening new connections",
					r.cfg.maxBody()/1024))
				warnedOverflow = true
			}

			if !warnedOther && s.Other.OK && s.Total.OK && s.Total.D > 0 &&
				float64(s.Other.D) > 0.2*float64(s.Total.D) {
				r.warn(fmt.Sprintf("round %d %s: %s unaccounted for (>20%% of total) — large body or an intermediary?",
					round, mode, s.Other.D.Round(time.Millisecond)))
				warnedOther = true
			}

			if s.Err != nil {
				consecutiveFails++
				if r.cfg.MaxFails > 0 && consecutiveFails >= r.cfg.MaxFails {
					r.warn(fmt.Sprintf("stopping after %d consecutive failures", consecutiveFails))
					return nil
				}
			} else {
				consecutiveFails = 0
			}

			if reason, stop := backoffTrigger(s); stop {
				r.warn("stopping: " + reason)
				return nil
			}
		}
	}
	return nil
}

// roundOrder alternates cold and warm so that neither mode systematically
// benefits from the other having just warmed a server-side cache (PLAN §4.3).
func (r *Runner) roundOrder(round int) []Mode {
	switch r.cfg.Mode {
	case ColdOnly:
		return []Mode{Cold}
	case WarmOnly:
		return []Mode{Warm}
	}
	switch r.cfg.Order {
	case "cold-first":
		return []Mode{Cold, Warm}
	case "warm-first":
		return []Mode{Warm, Cold}
	default:
		if round%2 == 1 {
			return []Mode{Cold, Warm}
		}
		return []Mode{Warm, Cold}
	}
}

func (r *Runner) probeOnce(ctx context.Context, mode Mode, round int) Sample {
	// A fresh deadline per request, covering DNS through body EOF. A cancelled
	// context is never carried into the next round (PLAN §4.2).
	reqCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	r.seq++
	if mode == Cold {
		return r.cold.probe(reqCtx, round, r.seq)
	}
	return r.warm.probe(reqCtx, round, r.seq)
}

// backoffTrigger implements the politeness stop: back off the moment the server
// says it is rate limited (PLAN §4.5).
func backoffTrigger(s Sample) (string, bool) {
	switch s.Status {
	case http.StatusTooManyRequests:
		return "429 Too Many Requests", true
	case http.StatusServiceUnavailable:
		if s.RetryAfter {
			return "503 with Retry-After", true
		}
	}
	return "", false
}

func sleepFor(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func sleepUntil(ctx context.Context, target time.Time) bool {
	return sleepFor(ctx, time.Until(target))
}

// normalizeTarget turns a bare host into a URL, defaulting to https.
func normalizeTarget(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty target")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}
	if u.User != nil {
		return nil, errors.New("URL credentials are not supported")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// NormalizeTarget is the exported entry point used by the CLI.
func NormalizeTarget(raw string) (*url.URL, error) { return normalizeTarget(raw) }
