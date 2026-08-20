package probe

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"time"
)

// DefaultMaxBody bounds how much of a response body is drained. HEAD is the
// default method so there is normally nothing to read (PLAN §4.2).
const DefaultMaxBody int64 = 64 << 10

// Config is everything the runner needs. main builds it from cli.Config.
type Config struct {
	URL     *url.URL
	Method  string // "" means detect via preflight
	Headers http.Header
	UA      string

	Count    int // 0 = until interrupted
	Interval time.Duration
	Timeout  time.Duration
	Warmup   int

	Mode  RunMode
	Order string // "alternate" | "cold-first" | "warm-first"

	HTTPVersion string // "auto" | "1.1" | "2"
	CacheBust   bool
	PinIP       bool
	IPVersion   int // 0 = auto, 4, 6
	Insecure    bool
	RootCAs     *x509.CertPool // test hook; nil uses the system pool

	MaxBody  int64
	MaxFails int // consecutive failures before giving up (PLAN §4.5)
}

// ipNetwork is the network string for LookupNetIP.
func (c Config) ipNetwork() string {
	switch c.IPVersion {
	case 4:
		return "ip4"
	case 6:
		return "ip6"
	}
	return "ip"
}

// tcpNetwork is the network string for Dial.
func (c Config) tcpNetwork() string {
	switch c.IPVersion {
	case 4:
		return "tcp4"
	case 6:
		return "tcp6"
	}
	return "tcp"
}

func (c Config) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return DefaultMaxBody
}
