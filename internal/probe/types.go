// Package probe measures the cost of an HTTPS request by decomposing it into
// phases, and owns every data type shared with stats and render (PLAN §5.1).
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Mode is the kind of an individual sample.
type Mode uint8

const (
	Cold Mode = iota
	Warm
)

func (m Mode) String() string {
	if m == Warm {
		return "warm"
	}
	return "cold"
}

// RunMode is the mode of the whole run, set by -m.
type RunMode uint8

const (
	Both RunMode = iota
	ColdOnly
	WarmOnly
)

func (r RunMode) String() string {
	switch r {
	case ColdOnly:
		return "cold"
	case WarmOnly:
		return "warm"
	}
	return "both"
}

// HasCold reports whether the run produces cold samples.
func (r RunMode) HasCold() bool { return r != WarmOnly }

// HasWarm reports whether the run produces warm samples.
func (r RunMode) HasWarm() bool { return r != ColdOnly }

// Phase separates "not measured" from a measured zero. A hook that never fired
// leaves OK false, which renders as "-" rather than 0ms (PLAN §4.1).
type Phase struct {
	D  time.Duration
	OK bool
}

// Measured builds a Phase that carries a real observation.
func Measured(d time.Duration) Phase { return Phase{D: d, OK: true} }

// Sample is one probe: one HTTP request decomposed into phases.
//
// Which fields are measured depends on Mode, and this comment is the only
// authority on it (PLAN §5.2):
//
//	cold: DNS, TCP, TLS, Srv measured; Wait not measured (it overlaps tcp+tls)
//	warm: Wait, Srv measured;          DNS, TCP, TLS not measured (no handshake)
//
// Consumers decide whether a *value exists* from Phase.OK, never by inferring
// it from Mode. Mode still decides where a sample belongs — which column, which
// block, which aggregate — because an early failure leaves every phase
// unmeasured in both modes alike.
type Sample struct {
	Round int // cold and warm of the same round share this: the paired-comparison key
	Mode  Mode

	DNS, TCP, TLS Phase
	Wait          Phase
	Srv           Phase
	Total         Phase
	Other         Phase // Total - (phase sum for this mode), PLAN §1.1

	Reused   bool // warm verification; the first warm request is always false
	Retries  int  // Transport re-attempts on a dead reused connection (PLAN §4.1)
	Overflow bool // body exceeded MaxBody, so the connection could not be reused
	Status   int  // 0 = no response
	Proto    string
	TLSVer   string
	ALPN     string
	Resumed  bool // TLS session ticket reuse, observable on cold (PLAN §1.2)
	ChainLen int  // peer certificate chain length, -v only
	Bytes    int64
	Addr     string

	RetryAfter bool // server sent Retry-After; with 503 it triggers the stop (PLAN §4.5)
	Secure     bool // the target is https, so a TLS phase is expected

	IsWarmup bool
	Err      error // nil means ok; 4xx/5xx are also nil (PLAN §4.4)
}

// Responded reports whether a response arrived, whatever its status code. It is
// deliberately not called OK, because Phase.OK means "measured" and confusing
// the two would silently invert failure handling.
func (s Sample) Responded() bool { return s.Err == nil }

// NewConn reports a warm sample that had to dial instead of reusing. It is not
// a failure; it is evidence about the server's keep-alive behaviour (PLAN §4.4).
func (s Sample) NewConn() bool { return s.Mode == Warm && s.Responded() && !s.Reused }

// Kind classifies the sample's error, ErrNone when it succeeded.
func (s Sample) Kind() ErrKind { return Classify(s.Err) }

// Timed reports whether the sample may enter the timing statistics. A warm
// sample that had to dial is ok but not comparable, so it is excluded and
// counted separately as new conn (PLAN §4.4).
func (s Sample) Timed() bool {
	if s.IsWarmup || s.Err != nil || !s.Total.OK {
		return false
	}
	if s.Mode == Warm && !s.Reused {
		return false
	}
	return true
}

// HandshakeSum returns what this cold sample paid to establish a connection,
// and whether every phase that applies was measured (PLAN §4.4).
//
// TLS is only required for an https target: over plain http there is no
// handshake, and demanding one would exclude every sample.
func (s Sample) HandshakeSum() (time.Duration, bool) {
	if s.Mode != Cold || !s.DNS.OK || !s.TCP.OK {
		return 0, false
	}
	total := s.DNS.D + s.TCP.D
	if s.Secure {
		if !s.TLS.OK {
			return 0, false
		}
		total += s.TLS.D
	}
	return total, true
}

// Note reports the trailing annotations for the sample's row (PLAN §2.1).
func (s Sample) Note() []string {
	var notes []string
	if s.IsWarmup {
		notes = append(notes, "warmup")
	}
	if s.NewConn() {
		notes = append(notes, "new conn")
	}
	if s.Retries > 0 {
		notes = append(notes, "retried")
	}
	if s.Overflow {
		notes = append(notes, "body>cap")
	}
	if s.Status == 429 {
		notes = append(notes, "429 limited")
	}
	return notes
}

// PhaseSum returns the non-overlapping phase sum for the sample's mode and
// whether every constituent phase was measured (PLAN §1.1).
func (s Sample) PhaseSum() (time.Duration, bool) {
	var total time.Duration
	parts := []Phase{s.Srv}
	if s.Mode == Cold {
		parts = append(parts, s.DNS, s.TCP, s.TLS)
	} else {
		parts = append(parts, s.Wait)
	}
	for _, p := range parts {
		if !p.OK {
			return 0, false
		}
		total += p.D
	}
	return total, true
}

// RunInfo describes the run as a whole. Addr, Proto and TLSVer require an
// actual connection, so RunInfo is filled by the preflight (PLAN §4.2, §5.3).
type RunInfo struct {
	URL      string
	Method   string
	Addr     string // "142.251.34.206:443"
	Proto    string // "h2"
	TLSVer   string // "TLS1.3"
	ALPN     string
	Pinned   bool
	DNSFirst Phase // first resolution, shown in the header when -m warm
	Bytes    int64
	Count    int
	Interval time.Duration
	Timeout  time.Duration // needed to render "timeout (5s)" in a failure cell
	Order    string        // "alternate" | "cold-first" | "warm-first"
	Mode     RunMode
	Host     string
	Warmup   int
	Version  string
}

// ErrKind classifies a failure. Slug is the stable identifier written to
// --json and --csv; Display is the free-form text shown in a table cell, and
// may be reworded between versions.
type ErrKind uint8

const (
	ErrNone ErrKind = iota
	ErrTimeout
	ErrCanceled
	ErrDNS
	ErrRefused
	ErrReset
	ErrUnreachable
	ErrCertExpired
	ErrCertName
	ErrCertUnknownCA
	ErrCertInvalid
	ErrTLS
	ErrConnClosed
	ErrBody
	ErrOther
)

var errText = map[ErrKind]struct{ slug, display string }{
	ErrNone:          {"", ""},
	ErrTimeout:       {"timeout", "timeout"},
	ErrCanceled:      {"canceled", "canceled"},
	ErrDNS:           {"dns_fail", "dns fail"},
	ErrRefused:       {"conn_refused", "conn refused"},
	ErrReset:         {"conn_reset", "conn reset"},
	ErrUnreachable:   {"unreachable", "unreachable"},
	ErrCertExpired:   {"cert_expired", "TLS: cert expired"},
	ErrCertName:      {"cert_name", "TLS: cert name"},
	ErrCertUnknownCA: {"cert_unknown_ca", "TLS: unknown CA"},
	ErrCertInvalid:   {"cert_invalid", "TLS: cert invalid"},
	ErrTLS:           {"tls_error", "TLS error"},
	ErrConnClosed:    {"conn_closed", "conn closed"},
	ErrBody:          {"body_error", "body error"},
	ErrOther:         {"error", "error"},
}

// Slug is the machine-readable identifier. Treat it as part of the --json and
// --csv schema.
func (k ErrKind) Slug() string { return errText[k].slug }

// Display is the human-readable table cell text.
func (k ErrKind) Display() string { return errText[k].display }

// Classify maps an error onto an ErrKind.
func Classify(err error) ErrKind {
	if err == nil {
		return ErrNone
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ErrTimeout
	case errors.Is(err, context.Canceled):
		return ErrCanceled
	}

	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		if certErr.Reason == x509.Expired {
			return ErrCertExpired
		}
		return ErrCertInvalid
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return ErrCertName
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return ErrCertUnknownCA
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return ErrCertInvalid
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return ErrTLS
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return ErrTLS
	}

	// DNSError is checked after the certificate cases: a name mismatch is a
	// certificate problem even though it mentions a host.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrDNS
	}

	// Match on the errno rather than the message: Windows words these errors
	// completely differently ("target machine actively refused it").
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, syscall.ECONNRESET):
		return ErrReset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return ErrUnreachable
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "actively refused"):
		return ErrRefused
	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "forcibly closed"):
		return ErrReset
	case strings.Contains(msg, "no such host"):
		return ErrDNS
	case strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no route to host"):
		return ErrUnreachable
	case strings.Contains(msg, "body read"):
		return ErrBody
	case strings.Contains(msg, "tls:"), strings.Contains(msg, "x509:"):
		return ErrTLS
	case strings.Contains(msg, "EOF"):
		return ErrConnClosed
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrTimeout
	}
	return ErrOther
}

// Reason is the short cell text used in the table (PLAN §2.3).
func Reason(err error) string { return Classify(err).Display() }

// DisplayHost renders the host for the summary heading.
func DisplayHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Hostname()
}
