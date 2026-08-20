package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// resolver times DNS itself instead of relying on the DNSStart/DNSDone hooks.
// With IP pinning on, the dialer already receives an address literal and those
// hooks never fire at all (PLAN §4.2).
type resolver struct {
	r       *net.Resolver
	network string // "ip4" | "ip6" | "ip"
}

func newResolver(network string) *resolver {
	return &resolver{r: net.DefaultResolver, network: network}
}

// lookup resolves host and reports how long it took. The duration is the whole
// point: it becomes the sample's dns phase.
func (rs *resolver) lookup(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	start := time.Now()
	addrs, err := rs.r.LookupNetIP(ctx, rs.network, host)
	d := time.Since(start)
	if err != nil {
		return nil, d, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	if len(out) == 0 {
		return nil, d, errors.New("no addresses for " + host)
	}
	return out, d, nil
}

// dialer optionally pins every connection to one address.
//
// The URL host is left untouched so the Transport still uses it for SNI and
// certificate verification; only the dial target is replaced (PLAN §4.2).
type dialer struct {
	d       *net.Dialer
	network string
	pinned  netip.Addr // invalid when pinning is off
	host    string     // only this host is rewritten, never a proxy address
}

func newDialer(network string, timeout time.Duration, pinned netip.Addr, host string) *dialer {
	return &dialer{
		d:       &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second},
		network: network,
		pinned:  pinned,
		host:    host,
	}
}

// setPin fixes the dial target. It must be called before the first dial, which
// in practice means before http.Client.Do is entered.
func (dl *dialer) setPin(a netip.Addr) { dl.pinned = a }

func (dl *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialNet := network
	if dl.network != "" && dl.network != "tcp" {
		dialNet = dl.network
	}
	if !dl.pinned.IsValid() {
		return dl.d.DialContext(ctx, dialNet, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// Rewriting anything but the origin host would redirect a proxy CONNECT to
	// the origin IP, which is the failure mode PLAN §4.2 calls out.
	if dl.host != "" && !strings.EqualFold(host, dl.host) {
		return dl.d.DialContext(ctx, dialNet, addr)
	}
	// JoinHostPort brackets IPv6 and preserves any zone identifier.
	target := net.JoinHostPort(dl.pinned.String(), port)
	return dl.d.DialContext(ctx, dialNet, target)
}

// hostPort returns host:port for the URL, defaulting the port by scheme.
func hostPort(host, scheme string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	port := "443"
	if scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(host, port)
}
