package probe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"time"
)

// coldRunner measures a connection that is built from scratch every time.
//
// Isolation is achieved with a fresh Transport per round plus DisableKeepAlives,
// which isolates the connection pool only. The OS DNS cache, TLS session
// tickets and any server-side state are deliberately not isolated (PLAN §4.2).
type coldRunner struct {
	cfg      Config
	rs       *resolver
	pinned   netip.Addr // preflight-fixed address, invalid when --no-pin-ip
	method   string
	sessions tls.ClientSessionCache
}

func newColdRunner(cfg Config, method string, pinned netip.Addr) *coldRunner {
	return &coldRunner{
		cfg:    cfg,
		rs:     newResolver(cfg.ipNetwork()),
		pinned: pinned,
		method: method,
		// One cache for every cold Transport, so a resumed handshake shows up
		// as a lower tls phase from the second round on (PLAN §1.2).
		sessions: tls.NewLRUClientSessionCache(8),
	}
}

// probe runs one cold measurement. The clock starts at the DNS lookup, which is
// the first cost a brand new connection pays (PLAN §1.1).
func (c *coldRunner) probe(ctx context.Context, round, seq int) Sample {
	// Everything that is not network work is built before the clock starts, so
	// that cold's total is not inflated by allocations that warm's total does
	// not contain. Without this the two modes are not comparable.
	dl := newDialer(c.cfg.tcpNetwork(), c.cfg.Timeout, c.pinned, c.cfg.URL.Hostname())
	tr := newTransportWith(transportOpts{
		cfg:          c.cfg,
		pinned:       c.pinned,
		disableProxy: c.cfg.PinIP,
		keepAlive:    false,
		sessions:     c.sessions,
	}, dl)
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, CheckRedirect: noFollow}
	req, err := buildRequest(ctx, c.cfg, c.method, seq)
	if err != nil {
		return Sample{Round: round, Mode: Cold, Err: err}
	}

	start := time.Now()

	addrs, d, err := c.rs.lookup(ctx, c.cfg.URL.Hostname())
	dns := Measured(d)
	if err != nil {
		return Sample{
			Round: round, Mode: Cold, DNS: dns,
			Total: Measured(time.Since(start)),
			Err:   err,
		}
	}
	// The cold lookup exists to be timed. It only steers the dial when pinning
	// is off, and even then the URL host is kept for SNI (PLAN §4.2).
	if !c.cfg.PinIP {
		dl.setPin(addrs[0])
	}

	ex := do(client, req, c.cfg.maxBody())
	total := time.Since(start)

	return finish(c.cfg, Cold, round, ex, total, dns)
}

// noFollow keeps one logical request to one connection. Following redirects
// would replay every hook per hop and blend several connections into one
// sample (PLAN §4.2).
func noFollow(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
