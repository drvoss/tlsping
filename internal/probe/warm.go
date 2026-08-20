package probe

import (
	"context"
	"net/http"
	"net/netip"
	"time"
)

// warmRunner measures the same connection over and over. One Transport is
// shared for the whole process; GotConn.Reused is what proves the connection
// really was reused (PLAN §4.2).
type warmRunner struct {
	cfg    Config
	tr     *http.Transport
	client *http.Client
	method string
}

func newWarmRunner(cfg Config, method string, pinned netip.Addr) *warmRunner {
	tr := newTransport(transportOpts{
		cfg:          cfg,
		pinned:       pinned,
		disableProxy: cfg.PinIP,
		keepAlive:    true,
	})
	return &warmRunner{
		cfg:    cfg,
		tr:     tr,
		client: &http.Client{Transport: tr, CheckRedirect: noFollow},
		method: method,
	}
}

// probe runs one warm measurement. There is no DNS lookup and no handshake to
// pay for, so the clock starts immediately before Do (PLAN §1.1).
func (w *warmRunner) probe(ctx context.Context, round, seq int) Sample {
	req, err := buildRequest(ctx, w.cfg, w.method, seq)
	if err != nil {
		return Sample{Round: round, Mode: Warm, Err: err}
	}

	start := time.Now()
	ex := do(w.client, req, w.cfg.maxBody())
	total := time.Since(start)

	// HTTP/1.x can only reuse a fully drained connection. Anything left on the
	// wire means this connection must be dropped rather than reused (PLAN §4.2).
	if !ex.drained {
		w.tr.CloseIdleConnections()
	}

	return finish(w.cfg, Warm, round, ex, total, Phase{})
}

func (w *warmRunner) close() { w.tr.CloseIdleConnections() }
