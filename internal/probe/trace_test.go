package probe

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"
)

// TestTracerAdoptsSuccessfulConnectAttempt covers Happy Eyeballs: several
// ConnectStart/Done pairs fire, they complete out of order, and only the one
// that actually connected may define tcp (PLAN §4.1).
func TestTracerAdoptsSuccessfulConnectAttempt(t *testing.T) {
	tr := newTracer()
	h := tr.trace()

	h.ConnectStart("tcp6", "[::1]:443")
	time.Sleep(2 * time.Millisecond)
	h.ConnectStart("tcp4", "127.0.0.1:443")
	// The v6 attempt finishes first, but it failed.
	h.ConnectDone("tcp6", "[::1]:443", errors.New("network unreachable"))
	time.Sleep(5 * time.Millisecond)
	h.ConnectDone("tcp4", "127.0.0.1:443", nil)

	got := tr.result()
	if !got.tcp.OK {
		t.Fatal("tcp not measured although one attempt succeeded")
	}
	if got.tcp.D < 5*time.Millisecond {
		t.Errorf("tcp = %v, want the successful v4 attempt (>=5ms), not the failed v6 one", got.tcp.D)
	}
}

// TestTracerIgnoresUnmatchedConnectDone makes sure a Done without a Start does
// not panic or invent a measurement.
func TestTracerIgnoresUnmatchedConnectDone(t *testing.T) {
	tr := newTracer()
	h := tr.trace()
	h.ConnectDone("tcp4", "127.0.0.1:443", nil)
	if tr.result().tcp.OK {
		t.Error("tcp measured from a ConnectDone with no matching ConnectStart")
	}
}

// TestTracerResetsOnRetry is the case codex raised: the Transport gives up on a
// dead reused connection and retries. Without a reset, wait/srv/Reused would
// each describe a different attempt (PLAN §4.1).
func TestTracerResetsOnRetry(t *testing.T) {
	tr := newTracer()
	h := tr.trace()

	// Attempt 1: got a pooled connection, wrote the request, then it died.
	h.GetConn("example.com:443")
	h.GotConn(httptrace.GotConnInfo{Conn: fakeConn{}, Reused: true})
	h.WroteRequest(httptrace.WroteRequestInfo{})
	h.GotFirstResponseByte()
	if !tr.result().srv.OK {
		t.Fatal("first attempt did not collect srv, so the reset is not exercised")
	}

	// Attempt 2: a fresh connection is dialled and the request is rewritten.
	h.GetConn("example.com:443")
	if tr.result().srv.OK {
		t.Fatal("srv from the abandoned attempt survived the retry reset")
	}
	h.ConnectStart("tcp4", "127.0.0.1:443")
	h.ConnectDone("tcp4", "127.0.0.1:443", nil)
	h.GotConn(httptrace.GotConnInfo{Conn: fakeConn{}, Reused: false})
	h.WroteRequest(httptrace.WroteRequestInfo{})
	h.GotFirstResponseByte()

	got := tr.result()
	if got.retries != 1 {
		t.Errorf("retries = %d, want 1", got.retries)
	}
	if got.reused {
		t.Error("Reused reflects the abandoned first attempt")
	}
	if !got.srv.OK {
		t.Fatal("srv not measured")
	}
	if !got.tcp.OK {
		t.Error("tcp from the retry attempt was lost")
	}
}

// TestTracerRecordsFailedHandshakeDuration keeps a TLS failure diagnosable: how
// long it took before failing is the useful part.
func TestTracerRecordsFailedHandshakeDuration(t *testing.T) {
	tr := newTracer()
	h := tr.trace()
	h.TLSHandshakeStart()
	time.Sleep(3 * time.Millisecond)
	h.TLSHandshakeDone(tls.ConnectionState{}, errors.New("x509: certificate has expired"))

	got := tr.result()
	if !got.tls.OK || got.tls.D < 3*time.Millisecond {
		t.Errorf("tls = %v (OK=%v), want the time spent before the handshake failed", got.tls.D, got.tls.OK)
	}
	if got.tlsVer != "" {
		t.Error("TLS version recorded from a failed handshake")
	}
}

// TestTracerSrvUnmeasuredWhenResponsePrecedesWrite guards against a negative
// srv when a server answers before the request finished being written.
func TestTracerSrvUnmeasuredWhenResponsePrecedesWrite(t *testing.T) {
	tr := newTracer()
	h := tr.trace()
	h.GotFirstResponseByte()
	h.WroteRequest(httptrace.WroteRequestInfo{})

	if got := tr.result(); got.srv.OK {
		t.Errorf("srv = %v, want unmeasured rather than a negative duration", got.srv.D)
	}
}

// TestTracerConcurrentHooks drives the collector from many goroutines at once,
// which is the situation PLAN §4.1 requires the mutex for. Meaningful under -race.
func TestTracerConcurrentHooks(t *testing.T) {
	tr := newTracer()
	h := tr.trace()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := "10.0.0." + string(rune('0'+i%10)) + ":443"
			h.ConnectStart("tcp4", addr)
			h.ConnectDone("tcp4", addr, nil)
			h.TLSHandshakeStart()
			h.TLSHandshakeDone(tls.ConnectionState{Version: tls.VersionTLS13}, nil)
			h.WroteRequest(httptrace.WroteRequestInfo{})
			h.GotFirstResponseByte()
			_ = tr.result()
		}(i)
	}
	wg.Wait()
}

type fakeConn struct{ net.Conn }

func (fakeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
