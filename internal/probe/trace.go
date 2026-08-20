package probe

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// tracer collects httptrace callbacks into durations.
//
// Hooks can fire concurrently (HTTP/2 streams, Happy Eyeballs dialing both
// families at once), so every field is behind the mutex. Durations are computed
// inside the hook rather than storing time.Time, because a stored wall clock
// loses its monotonic reading (PLAN §4.1).
type tracer struct {
	mu sync.Mutex

	getConnAt   time.Time
	haveGetConn bool
	wait        Phase

	// ConnectStart/Done may fire several times. Every attempt is recorded and
	// the one that actually succeeded is adopted (PLAN §4.1).
	attempts []*connAttempt
	tcp      Phase

	tlsStartAt time.Time
	haveTLS    bool
	tls        Phase
	tlsVer     string
	alpn       string
	resumed    bool
	chainLen   int

	wroteAt   time.Time
	haveWrote bool
	srv       Phase

	reused     bool
	remoteAddr string
	idleTime   time.Duration

	retries int
}

// resetAttempt drops everything that belongs to a superseded attempt. Called
// with the mutex held.
func (t *tracer) resetAttempt() {
	t.wait = Phase{}
	t.tcp = Phase{}
	t.tls = Phase{}
	t.srv = Phase{}
	t.attempts = nil
	t.haveTLS = false
	t.haveWrote = false
	t.tlsVer, t.alpn = "", ""
	t.resumed, t.chainLen = false, 0
}

type connAttempt struct {
	key   string
	start time.Time
	done  bool
}

func newTracer() *tracer { return &tracer{} }

// trace returns the ClientTrace to attach to the request context.
func (t *tracer) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.haveGetConn {
				// A second GetConn for the same request means the Transport is
				// retrying, typically because a reused connection was already
				// dead. Everything collected so far describes the abandoned
				// attempt, so it is discarded: otherwise wait, srv and Reused
				// would each describe a different attempt.
				t.retries++
				t.resetAttempt()
			}
			t.getConnAt = now
			t.haveGetConn = true
		},

		GotConn: func(info httptrace.GotConnInfo) {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.haveGetConn && !t.wait.OK {
				t.wait = Measured(now.Sub(t.getConnAt))
			}
			t.reused = info.Reused
			t.idleTime = info.IdleTime
			if info.Conn != nil {
				if ra := info.Conn.RemoteAddr(); ra != nil {
					t.remoteAddr = ra.String()
				}
			}
		},

		ConnectStart: func(network, addr string) {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			t.attempts = append(t.attempts, &connAttempt{key: network + "|" + addr, start: now})
		},

		ConnectDone: func(network, addr string, err error) {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			a := t.findAttempt(network + "|" + addr)
			if a == nil {
				return
			}
			a.done = true
			if err == nil && !t.tcp.OK {
				// Adopt the interval of the attempt that actually connected.
				t.tcp = Measured(now.Sub(a.start))
			}
		},

		TLSHandshakeStart: func() {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.haveTLS {
				t.tlsStartAt = now
				t.haveTLS = true
			}
		},

		TLSHandshakeDone: func(st tls.ConnectionState, err error) {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.haveTLS || t.tls.OK {
				return
			}
			// The hook fires on failure too, and the time spent before the
			// handshake failed is exactly what makes a TLS failure diagnosable.
			t.tls = Measured(now.Sub(t.tlsStartAt))
			if err != nil {
				return
			}
			t.tlsVer = tlsVersion(st.Version)
			t.alpn = st.NegotiatedProtocol
			t.resumed = st.DidResume
			t.chainLen = len(st.PeerCertificates)
		},

		WroteRequest: func(httptrace.WroteRequestInfo) {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.haveWrote {
				t.wroteAt = now
				t.haveWrote = true
			}
		},

		GotFirstResponseByte: func() {
			now := time.Now()
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.haveWrote && !t.srv.OK {
				t.srv = Measured(now.Sub(t.wroteAt))
			}
		},
	}
}

// findAttempt returns the oldest attempt for key that has not completed yet.
func (t *tracer) findAttempt(key string) *connAttempt {
	for _, a := range t.attempts {
		if a.key == key && !a.done {
			return a
		}
	}
	return nil
}

// result is an immutable snapshot of what the hooks collected.
type result struct {
	wait, tcp, tls, srv Phase
	tlsVer, alpn        string
	resumed             bool
	chainLen            int
	reused              bool
	remoteAddr          string
	retries             int
}

func (t *tracer) result() result {
	t.mu.Lock()
	defer t.mu.Unlock()
	return result{
		wait: t.wait, tcp: t.tcp, tls: t.tls, srv: t.srv,
		tlsVer: t.tlsVer, alpn: t.alpn, resumed: t.resumed, chainLen: t.chainLen,
		reused: t.reused, remoteAddr: t.remoteAddr, retries: t.retries,
	}
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return ""
}
