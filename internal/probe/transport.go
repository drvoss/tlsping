package probe

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"time"
)

// transportOpts describes one Transport. cold builds a fresh one per round with
// keepAlive off; warm builds exactly one and shares it for the whole run.
type transportOpts struct {
	cfg          Config
	pinned       netip.Addr
	disableProxy bool
	keepAlive    bool
	// sessions is shared across every cold Transport so TLS session resumption
	// is observable: the tls phase drops from the second cold round on
	// (PLAN §1.2). A nil cache disables resumption entirely.
	sessions tls.ClientSessionCache
}

func newTransport(o transportOpts) *http.Transport {
	dl := newDialer(o.cfg.tcpNetwork(), o.cfg.Timeout, o.pinned, o.cfg.URL.Hostname())
	return newTransportWith(o, dl)
}

// newTransportWith lets the caller keep the dialer, so a cold probe can build
// the Transport before starting its clock and only fill in the resolved
// address afterwards (see coldRunner.probe).
func newTransportWith(o transportOpts, dl *dialer) *http.Transport {
	tr := &http.Transport{
		DialContext:           dl.DialContext,
		DisableKeepAlives:     !o.keepAlive,
		DisableCompression:    true,
		TLSHandshakeTimeout:   o.cfg.Timeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       0, // no idle expiry: the interval may exceed any default
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: o.cfg.Insecure, //nolint:gosec // -k is an explicit opt-in
			RootCAs:            o.cfg.RootCAs,
			ClientSessionCache: o.sessions,
		},
	}

	// Pinning replaces the dial target, so a proxy address could be rewritten
	// too. Disable proxying whenever the address is pinned (PLAN §4.2).
	if o.disableProxy {
		tr.Proxy = nil
	} else {
		tr.Proxy = http.ProxyFromEnvironment
	}

	// ForceAttemptHTTP2 only permits negotiation. Protocols states the allowed
	// set explicitly; the outcome is verified against ProtoMajor (PLAN §4.6).
	var p http.Protocols
	switch o.cfg.HTTPVersion {
	case "1.1":
		p.SetHTTP1(true)
	case "2":
		p.SetHTTP2(true)
	default:
		p.SetHTTP1(true)
		p.SetHTTP2(true)
	}
	tr.Protocols = &p

	return tr
}

// protoLabel renders the negotiated protocol for display.
func protoLabel(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if resp.ProtoMajor == 2 {
		return "h2"
	}
	if resp.ProtoMajor == 1 && resp.ProtoMinor == 1 {
		return "http/1.1"
	}
	return resp.Proto
}
