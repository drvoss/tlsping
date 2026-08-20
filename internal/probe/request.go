package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"time"
)

// exchange is the outcome of one HTTP round trip, before it is folded into a
// Sample with mode-specific totals.
type exchange struct {
	res      result
	status   int
	proto    string
	bytes    int64
	overflow bool // body exceeded maxBody
	drained  bool // false = the connection cannot be reused
	header   http.Header
	err      error
}

// buildRequest assembles the request for one probe.
func buildRequest(ctx context.Context, cfg Config, method string, seq int) (*http.Request, error) {
	u := *cfg.URL
	if cfg.CacheBust {
		q := u.Query()
		q.Set("_", strconv.Itoa(seq))
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range cfg.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", cfg.UA)
	}
	if method == http.MethodGet && req.Header.Get("Range") == "" {
		// Keep the GET fallback from turning into a bandwidth test.
		req.Header.Set("Range", "bytes=0-0")
	}
	return req, nil
}

// do performs one request with tracing attached and drains the body.
//
// The body is read with maxBody+1 so the caller can tell a genuine EOF from
// hitting the cap: io.LimitReader returns EOF for both (PLAN §4.2).
func do(client *http.Client, req *http.Request, maxBody int64) exchange {
	t := newTracer()
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), t.trace()))

	resp, err := client.Do(req)
	if err != nil {
		return exchange{res: t.result(), err: unwrapURLError(err)}
	}

	n, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody+1))
	overflow := n > maxBody
	closeErr := resp.Body.Close()

	ex := exchange{
		res:      t.result(),
		status:   resp.StatusCode,
		proto:    protoLabel(resp),
		bytes:    n,
		overflow: overflow,
		drained:  !overflow && copyErr == nil && closeErr == nil,
		header:   resp.Header,
	}
	// A body that could not be read is a failed measurement, not a success with
	// a short body (PLAN §4.4).
	switch {
	case copyErr != nil:
		ex.err = fmt.Errorf("body read: %w", copyErr)
	case closeErr != nil && !overflow:
		// Closing early on overflow is deliberate, so only an unexpected close
		// failure after a complete read means the response was truncated.
		ex.err = fmt.Errorf("body read: close: %w", closeErr)
	}
	return ex
}

// unwrapURLError strips the *url.Error wrapper so Reason sees the cause and the
// message does not repeat the URL on every row.
func unwrapURLError(err error) error {
	var ue *url.Error
	if e, ok := err.(*url.Error); ok {
		ue = e
	}
	if ue != nil && ue.Err != nil {
		return ue.Err
	}
	return err
}

// finish folds an exchange plus a measured total into a Sample.
func finish(cfg Config, mode Mode, round int, ex exchange, total time.Duration, dns Phase) Sample {
	s := Sample{
		Round:    round,
		Mode:     mode,
		Secure:   cfg.URL.Scheme == "https",
		Srv:      ex.res.srv,
		Total:    Measured(total),
		Reused:   ex.res.reused,
		Retries:  ex.res.retries,
		Overflow: ex.overflow,
		Status:   ex.status,
		Proto:    ex.proto,
		TLSVer:   ex.res.tlsVer,
		ALPN:     ex.res.alpn,
		Resumed:  ex.res.resumed,
		ChainLen: ex.res.chainLen,
		Bytes:    ex.bytes,
		Addr:     ex.res.remoteAddr,
		Err:      ex.err,
	}
	if ex.header != nil {
		s.RetryAfter = ex.header.Get("Retry-After") != ""
	}
	if mode == Cold {
		// wait spans GetConn->GotConn, which on a new connection swallows the
		// dial and the handshake. Recording it would double-count (PLAN §1.1).
		s.DNS = dns
		s.TCP = ex.res.tcp
		s.TLS = ex.res.tls
	} else {
		s.Wait = ex.res.wait
	}
	// other is only reported when it is a coherent residual. A negative value
	// would mean the phases did not nest inside total, so report nothing rather
	// than a number that contradicts PLAN §1.1.
	if sum, ok := s.PhaseSum(); ok && total >= sum {
		s.Other = Measured(total - sum)
	}
	return s
}
