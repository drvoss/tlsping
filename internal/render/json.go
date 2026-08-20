package render

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/drvoss/tlsping/internal/probe"
	"github.com/drvoss/tlsping/internal/stats"
)

// SchemaVersion identifies the --json and --csv layout. Bump it on any
// incompatible change so consumers can pin.
const SchemaVersion = 1

// jsonPhase is the wire form of probe.Phase: null when the phase was never
// measured, which is a different thing from 0 (PLAN §4.1).
type jsonPhase struct{ ms *float64 }

func (p jsonPhase) MarshalJSON() ([]byte, error) {
	if p.ms == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*p.ms)
}

func phaseJSON(p probe.Phase) jsonPhase {
	if !p.OK {
		return jsonPhase{}
	}
	v := float64(p.D.Microseconds()) / 1000
	return jsonPhase{ms: &v}
}

type jsonSample struct {
	Round    int       `json:"round"`
	Mode     string    `json:"mode"`
	DNS      jsonPhase `json:"dns_ms"`
	TCP      jsonPhase `json:"tcp_ms"`
	TLS      jsonPhase `json:"tls_ms"`
	Wait     jsonPhase `json:"wait_ms"`
	Srv      jsonPhase `json:"srv_ms"`
	Total    jsonPhase `json:"total_ms"`
	Other    jsonPhase `json:"other_ms"`
	Reused   bool      `json:"reused"`
	NewConn  bool      `json:"new_conn"`
	Retries  int       `json:"retries"`
	Status   int       `json:"status"`
	Proto    string    `json:"proto,omitempty"`
	TLSVer   string    `json:"tls_version,omitempty"`
	ALPN     string    `json:"alpn,omitempty"`
	Resumed  bool      `json:"tls_resumed"`
	ChainLen *int      `json:"cert_chain_len,omitempty"`
	Bytes    int64     `json:"bytes"`
	Addr     string    `json:"addr,omitempty"`
	Warmup   bool      `json:"warmup"`
	Overflow bool      `json:"body_overflow"`
	ErrKind  string    `json:"error_kind,omitempty"`
	Err      string    `json:"error,omitempty"`
}

func toJSONSample(s probe.Sample) jsonSample {
	js := jsonSample{
		Round: s.Round, Mode: s.Mode.String(),
		DNS:    phaseJSON(s.DNS),
		TCP:    phaseJSON(s.TCP),
		TLS:    phaseJSON(s.TLS),
		Wait:   phaseJSON(s.Wait),
		Srv:    phaseJSON(s.Srv),
		Total:  phaseJSON(s.Total),
		Other:  phaseJSON(s.Other),
		Reused: s.Reused, NewConn: s.NewConn(), Retries: s.Retries,
		Status: s.Status, Proto: s.Proto, TLSVer: s.TLSVer, ALPN: s.ALPN,
		Resumed: s.Resumed, Bytes: s.Bytes, Addr: s.Addr,
		Warmup: s.IsWarmup, Overflow: s.Overflow,
	}
	// Only present when a handshake actually happened, so a zero cannot be
	// misread as "no certificates".
	if s.TLSVer != "" {
		n := s.ChainLen
		js.ChainLen = &n
	}
	if s.Err != nil {
		js.ErrKind = s.Kind().Slug()
		js.Err = s.Err.Error()
	}
	return js
}

type jsonAgg struct {
	N      int       `json:"n"`
	Sent   int       `json:"sent"`
	OK     int       `json:"ok"`
	Loss   float64   `json:"loss"`
	Min    jsonPhase `json:"min_ms"`
	Mean   jsonPhase `json:"mean_ms"`
	Median jsonPhase `json:"median_ms"`
	Max    jsonPhase `json:"max_ms"`
	Mdev   jsonPhase `json:"mdev_ms"`
	P95    jsonPhase `json:"p95_ms"`
}

func toJSONAgg(a stats.Agg) jsonAgg {
	// With no usable sample every figure is null rather than 0, so a consumer
	// cannot mistake "nothing measured" for "measured as zero".
	mk := func(d time.Duration) jsonPhase {
		if a.N == 0 {
			return jsonPhase{}
		}
		return phaseJSON(probe.Measured(d))
	}
	return jsonAgg{
		N: a.N, Sent: a.Sent, OK: a.OK, Loss: a.Loss,
		Min:    mk(a.Min),
		Mean:   mk(a.Mean),
		Median: mk(a.Median),
		Max:    mk(a.Max),
		Mdev:   mk(a.Mdev),
		P95:    phaseJSON(a.P95),
	}
}

type jsonDoc struct {
	Schema  int          `json:"schema"`
	Version string       `json:"tlsping_version,omitempty"`
	Run     jsonRun      `json:"run"`
	Samples []jsonSample `json:"samples"`
	Summary jsonSummary  `json:"summary"`
	Warns   []string     `json:"warnings,omitempty"`
}

type jsonRun struct {
	URL      string    `json:"url"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	Addr     string    `json:"addr"`
	Proto    string    `json:"proto"`
	TLSVer   string    `json:"tls_version,omitempty"`
	ALPN     string    `json:"alpn,omitempty"`
	Pinned   bool      `json:"ip_pinned"`
	DNSFirst jsonPhase `json:"dns_first_ms"`
	Count    int       `json:"count"`
	Interval float64   `json:"interval_ms"`
	Timeout  float64   `json:"timeout_ms"`
	Order    string    `json:"order"`
	Mode     string    `json:"mode"`
	Warmup   int       `json:"warmup"`
}

type jsonSummary struct {
	Cold            jsonAgg   `json:"cold"`
	Warm            jsonAgg   `json:"warm"`
	NewConn         int       `json:"new_conn"`
	Overhead        float64   `json:"handshake_overhead_ms"`
	OverheadDNS     float64   `json:"handshake_dns_ms"`
	OverheadTCP     float64   `json:"handshake_tcp_ms"`
	OverheadTLS     float64   `json:"handshake_tls_ms"`
	OverheadSkipped int       `json:"handshake_excluded"`
	Gain            float64   `json:"keepalive_gain_ms"`
	PairedGain      jsonPhase `json:"paired_gain_ms"`
	TLSResumed      int       `json:"tls_resumed"`
	ColdSamples     int       `json:"cold_samples"`
	Elapsed         float64   `json:"elapsed_ms"`
}

// JSONRenderer buffers everything and emits one document, which is what makes
// the output convenient to pipe into jq.
type JSONRenderer struct {
	out     *errWriter
	errw    io.Writer
	info    probe.RunInfo
	samples []probe.Sample
	warns   []string
	version string
}

func NewJSON(out, errw io.Writer, version string) *JSONRenderer {
	return &JSONRenderer{out: &errWriter{w: out}, errw: errw, version: version}
}

// Err reports the first failure writing the document.
func (j *JSONRenderer) Err() error { return j.out.err }

func (j *JSONRenderer) Header(info probe.RunInfo) { j.info = info }

func (j *JSONRenderer) Sample(s probe.Sample) { j.samples = append(j.samples, s) }

func (j *JSONRenderer) Warn(msg string) {
	j.warns = append(j.warns, msg)
	fmt.Fprintln(j.errw, "tlsping: "+msg)
}

func (j *JSONRenderer) Summary(s stats.Summary) {
	doc := jsonDoc{
		Schema:  SchemaVersion,
		Version: j.version,
		Run: jsonRun{
			URL: j.info.URL, Host: j.info.Host, Method: j.info.Method,
			Addr: j.info.Addr, Proto: j.info.Proto, TLSVer: j.info.TLSVer, ALPN: j.info.ALPN,
			Pinned: j.info.Pinned, DNSFirst: phaseJSON(j.info.DNSFirst),
			Count: j.info.Count, Interval: msFloat(j.info.Interval), Timeout: msFloat(j.info.Timeout),
			Order: j.info.Order, Mode: j.info.Mode.String(), Warmup: j.info.Warmup,
		},
		Samples: make([]jsonSample, 0, len(j.samples)),
		Summary: jsonSummary{
			Cold: toJSONAgg(s.Cold), Warm: toJSONAgg(s.Warm),
			NewConn:         s.NewConn,
			Overhead:        msFloat(s.Overhead),
			OverheadDNS:     msFloat(s.OverheadDNS),
			OverheadTCP:     msFloat(s.OverheadTCP),
			OverheadTLS:     msFloat(s.OverheadTLS),
			OverheadSkipped: s.OverheadSkipped,
			// Signed on purpose: a negative gain is a real signal (PLAN §2.1).
			Gain:        msFloat(s.Gain),
			PairedGain:  phaseJSON(s.PairedGain),
			TLSResumed:  s.Resumed,
			ColdSamples: s.ColdSeen,
			Elapsed:     msFloat(s.Elapsed),
		},
		Warns: j.warns,
	}
	for _, smp := range j.samples {
		doc.Samples = append(doc.Samples, toJSONSample(smp))
	}

	enc := json.NewEncoder(j.out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintln(j.errw, "tlsping: json encode:", err)
		if j.out.err == nil {
			j.out.err = err
		}
	}
}

// CSVRenderer streams one row per sample. The summary is not represented;
// --json carries it.
type CSVRenderer struct {
	w    *csv.Writer
	out  *errWriter
	errw io.Writer
	info probe.RunInfo
	head bool
}

func NewCSV(out, errw io.Writer) *CSVRenderer {
	ew := &errWriter{w: out}
	return &CSVRenderer{w: csv.NewWriter(ew), out: ew, errw: errw}
}

// Err reports the first failure writing rows.
func (c *CSVRenderer) Err() error {
	if c.out.err != nil {
		return c.out.err
	}
	return c.w.Error()
}

var csvHeader = []string{
	"round", "mode", "warmup", "dns_ms", "tcp_ms", "tls_ms", "wait_ms", "srv_ms",
	"total_ms", "other_ms", "reused", "new_conn", "retries", "status", "proto",
	"tls_version", "alpn", "tls_resumed", "cert_chain_len", "bytes", "addr",
	"body_overflow", "error_kind", "error",
}

func (c *CSVRenderer) Header(info probe.RunInfo) { c.info = info }

func (c *CSVRenderer) Sample(s probe.Sample) {
	if !c.head {
		_ = c.w.Write(csvHeader)
		c.head = true
	}
	chain := ""
	if s.TLSVer != "" {
		chain = strconv.Itoa(s.ChainLen)
	}
	errKind, errMsg := "", ""
	if s.Err != nil {
		errKind, errMsg = s.Kind().Slug(), s.Err.Error()
	}
	_ = c.w.Write([]string{
		strconv.Itoa(s.Round), s.Mode.String(), boolStr(s.IsWarmup),
		csvPhase(s.DNS), csvPhase(s.TCP), csvPhase(s.TLS), csvPhase(s.Wait),
		csvPhase(s.Srv), csvPhase(s.Total), csvPhase(s.Other),
		boolStr(s.Reused), boolStr(s.NewConn()), strconv.Itoa(s.Retries),
		strconv.Itoa(s.Status), s.Proto, s.TLSVer, s.ALPN, boolStr(s.Resumed),
		chain, strconv.FormatInt(s.Bytes, 10), s.Addr,
		boolStr(s.Overflow), errKind, errMsg,
	})
	c.w.Flush()
}

func (c *CSVRenderer) Warn(msg string) { fmt.Fprintln(c.errw, "tlsping: "+msg) }

func (c *CSVRenderer) Summary(stats.Summary) {
	c.w.Flush()
	if err := c.w.Error(); err != nil {
		fmt.Fprintln(c.errw, "tlsping: csv:", err)
	}
}

// csvPhase leaves an unmeasured phase as an empty field, never 0.
func csvPhase(p probe.Phase) string {
	if !p.OK {
		return ""
	}
	return strconv.FormatFloat(float64(p.D.Microseconds())/1000, 'f', 3, 64)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// msFloat renders a duration as milliseconds with sub-millisecond detail.
func msFloat(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
