package render

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drvoss/tlsping/internal/probe"
	"github.com/drvoss/tlsping/internal/stats"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func testInfo() probe.RunInfo {
	return probe.RunInfo{
		URL: "https://example.com/", Host: "example.com", Method: "HEAD",
		Addr: "93.184.216.34:443", Proto: "h2", TLSVer: "TLS1.3", ALPN: "h2",
		Pinned: true, DNSFirst: probe.Measured(ms(12)), Bytes: 0,
		Count: 6, Interval: time.Second, Timeout: 5 * time.Second,
		Order: "alternate", Mode: probe.Both, Warmup: 1,
	}
}

func cold(round, dns, tcp, tlsD, srv, total int) probe.Sample {
	return probe.Sample{
		Round: round, Mode: probe.Cold, Secure: true,
		DNS: probe.Measured(ms(dns)), TCP: probe.Measured(ms(tcp)),
		TLS: probe.Measured(ms(tlsD)), Srv: probe.Measured(ms(srv)),
		Total:  probe.Measured(ms(total)),
		Other:  probe.Measured(ms(total - dns - tcp - tlsD - srv)),
		Status: 200, Proto: "h2", TLSVer: "TLS1.3", ALPN: "h2", ChainLen: 3,
	}
}

func warm(round, wait, srv, total int, reused bool) probe.Sample {
	return probe.Sample{
		Round: round, Mode: probe.Warm, Secure: true,
		Wait: probe.Measured(ms(wait)), Srv: probe.Measured(ms(srv)),
		Total:  probe.Measured(ms(total)),
		Other:  probe.Measured(ms(total - wait - srv)),
		Reused: reused, Status: 200, Proto: "h2",
	}
}

// fixture is a deterministic run: a warmup round, four normal rounds, and one
// round where the cold side timed out (PLAN §2.3).
func fixture() []probe.Sample {
	c1 := cold(1, 12, 31, 64, 33, 142)
	w1 := warm(1, 95, 33, 129, false)
	c1.IsWarmup, w1.IsWarmup = true, true

	timedOut := probe.Sample{
		Round: 6, Mode: probe.Cold, Secure: true,
		DNS:   probe.Measured(ms(0)),
		Total: probe.Measured(5 * time.Second),
		Err:   context.DeadlineExceeded,
	}

	return []probe.Sample{
		c1, w1,
		cold(2, 0, 31, 63, 32, 128), warm(2, 0, 32, 33, true),
		cold(3, 0, 33, 67, 38, 140), warm(3, 0, 37, 38, true),
		cold(4, 0, 32, 65, 34, 133), warm(4, 0, 34, 35, true),
		// Deliberately slow so the running-median highlight has something to
		// catch when colour is on.
		cold(5, 0, 34, 71, 41, 148), warm(5, 1, 40, 42, true),
		timedOut, warm(6, 0, 33, 34, true),
	}
}

func renderFixture(t *testing.T, opt Options) string {
	t.Helper()
	var out, errw bytes.Buffer
	r := NewTable(&out, &errw, opt)

	info := testInfo()
	r.Header(info)
	samples := fixture()
	for _, s := range samples {
		r.Sample(s)
	}
	r.Summary(stats.Compute(samples, 6200*time.Millisecond, 1))
	return out.String()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run: go test ./internal/render -update)", path, err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestGoldenWide(t *testing.T) {
	golden(t, "wide.txt", renderFixture(t, Options{Width: 140, Layout: LayoutWide}))
}

func TestGoldenMid(t *testing.T) {
	golden(t, "mid.txt", renderFixture(t, Options{Width: 80, Layout: LayoutMid}))
}

func TestGoldenMin(t *testing.T) {
	golden(t, "min.txt", renderFixture(t, Options{Width: 60, Layout: LayoutMin}))
}

func TestGoldenVerbose(t *testing.T) {
	golden(t, "verbose.txt", renderFixture(t, Options{Width: 140, Layout: LayoutWide, Verbose: true}))
}

func TestGoldenQuiet(t *testing.T) {
	golden(t, "quiet.txt", renderFixture(t, Options{Width: 140, Layout: LayoutWide, Quiet: true}))
}

// TestFailureCellStaysAligned is the alignment guarantee from PLAN §2.3: the
// failed side is filled with a reason and the other side still prints normally,
// without the row losing its grid.
func TestFailureCellStaysAligned(t *testing.T) {
	out := renderFixture(t, Options{Width: 140, Layout: LayoutWide})
	lines := strings.Split(out, "\n")

	var sep string
	var rows []string
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "-----+"):
			sep = l
		case strings.HasPrefix(l, "   ") && strings.Contains(l, "|"):
			rows = append(rows, l)
		}
	}
	if sep == "" {
		t.Fatal("no separator line found")
	}
	if len(rows) < 6 {
		t.Fatalf("found %d data rows, want 6", len(rows))
	}

	// Every row must place its bars exactly where the separator places its
	// plus signs.
	wantBars := barPositions(sep, '+')
	for _, row := range rows {
		if got := barPositions(row, '|'); !equalInts(got, wantBars) {
			t.Errorf("row %q has separators at %v, want %v", row, got, wantBars)
		}
	}

	failing := rows[len(rows)-1]
	if !strings.Contains(failing, "timeout (5s)") {
		t.Errorf("failure row %q does not carry the timeout reason with its limit", failing)
	}
	if !strings.Contains(failing, "-/200") {
		t.Errorf("failure row %q does not show the per-mode code as -/200", failing)
	}
}

func barPositions(s string, c rune) []int {
	var out []int
	for i, r := range s {
		if r == c {
			out = append(out, i)
		}
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGridIsCountedInCellsNotBytes guards the fixed-width grid against
// multi-byte text: measuring with len() would shift every bar on the row.
func TestGridIsCountedInCellsNotBytes(t *testing.T) {
	cases := []struct {
		in string
		w  int
	}{
		{"abc", 8},
		{"TLS: cert expired", 8}, // must be cut
		{"타임아웃", 8},              // multi-byte, fits in cells
		{"타임아웃이 발생했습니다", 8},      // multi-byte, must be cut
		{"a·b", 8},               // middle dot is two bytes
		{"exactly8", 8},          // exact fit
	}
	for _, c := range cases {
		if got := cells(pad(c.in, c.w)); got != c.w {
			t.Errorf("pad(%q, %d) is %d cells, want %d", c.in, c.w, got, c.w)
		}
		if got := cells(center(c.in, c.w)); got != c.w {
			t.Errorf("center(%q, %d) is %d cells, want %d", c.in, c.w, got, c.w)
		}
	}
	if got := cut("abcdefgh", 4); got != "abc~" {
		t.Errorf("cut = %q, want %q: a truncation must be visible", got, "abc~")
	}
	if got := cut("abc", 8); got != "abc" {
		t.Errorf("cut shortened a string that already fits: %q", got)
	}
}

// TestFailureCellFitsEveryReason: no reason string may silently break the grid.
func TestFailureCellFitsEveryReason(t *testing.T) {
	kinds := []probe.ErrKind{
		probe.ErrTimeout, probe.ErrCanceled, probe.ErrDNS, probe.ErrRefused,
		probe.ErrReset, probe.ErrUnreachable, probe.ErrCertExpired, probe.ErrCertName,
		probe.ErrCertUnknownCA, probe.ErrCertInvalid, probe.ErrTLS, probe.ErrConnClosed,
		probe.ErrBody, probe.ErrOther,
	}
	for _, k := range kinds {
		for _, w := range []int{coldW, warmW, cellW} {
			if got := cells(center(k.Display(), w)); got != w {
				t.Errorf("reason %q in a %d-cell column rendered %d cells", k.Display(), w, got)
			}
		}
	}
}

// TestIncompleteRoundIsStillPrinted covers a run that stops between the cold
// and the warm probe: the buffered sample must reach the output rather than be
// dropped while it waits for a partner that never arrives.
func TestIncompleteRoundIsStillPrinted(t *testing.T) {
	for _, first := range []probe.Mode{probe.Cold, probe.Warm} {
		name := "cold-first"
		s := cold(7, 0, 30, 60, 30, 122)
		if first == probe.Warm {
			name, s = "warm-first", warm(7, 0, 31, 32, true)
		}
		t.Run(name, func(t *testing.T) {
			var out, errw bytes.Buffer
			r := NewTable(&out, &errw, Options{Width: 140, Layout: LayoutWide})
			r.Header(testInfo()) // Mode: Both, so this round stays incomplete
			r.Sample(s)
			r.Summary(stats.Compute([]probe.Sample{s}, time.Second, 0))

			if !strings.Contains(out.String(), "   7 |") {
				t.Errorf("round 7 never printed after an interrupted round:\n%s", out.String())
			}
		})
	}
}

func TestWriteFailureIsReported(t *testing.T) {
	var errw bytes.Buffer
	r := NewTable(failingWriter{}, &errw, Options{Width: 140, Layout: LayoutWide})
	r.Header(testInfo())
	for _, s := range fixture() {
		r.Sample(s)
	}
	r.Summary(stats.Compute(fixture(), time.Second, 1))

	if r.Err() == nil {
		t.Error("a failing stdout was reported as a successful render")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

var errWriteFailed = errors.New("write failed")

func TestPickLayout(t *testing.T) {
	cases := []struct {
		w    int
		want Layout
	}{
		{200, LayoutWide}, {140, LayoutWide}, {100, LayoutWide},
		{99, LayoutMid}, {80, LayoutMid}, {70, LayoutMid},
		{69, LayoutMin}, {60, LayoutMin}, {40, LayoutMin}, {0, LayoutMin},
	}
	for _, c := range cases {
		if got := PickLayout(c.w); got != c.want {
			t.Errorf("PickLayout(%d) = %v, want %v", c.w, got, c.want)
		}
	}
}

// TestWideFitsWithinWidth guards the reason the fallbacks exist: the wide table
// must not overflow the narrowest terminal that selects it.
func TestWideFitsWithinWidth(t *testing.T) {
	out := renderFixture(t, Options{Width: WideMin, Layout: LayoutWide})
	for _, l := range strings.Split(out, "\n") {
		if len(l) > WideMin {
			t.Errorf("line is %d columns, over the %d that selected this layout:\n%s", len(l), WideMin, l)
		}
	}
}

func TestMidFitsWithinWidth(t *testing.T) {
	out := renderFixture(t, Options{Width: MidMin, Layout: LayoutMid})
	for _, l := range strings.Split(out, "\n") {
		if len(l) > MidMin {
			t.Errorf("line is %d columns, over the %d that selected this layout:\n%s", len(l), MidMin, l)
		}
	}
}

func TestSingleModeDropsOtherColumn(t *testing.T) {
	var out, errw bytes.Buffer
	info := testInfo()
	info.Mode = probe.ColdOnly
	r := NewTable(&out, &errw, Options{Width: 140, Layout: LayoutWide})
	r.Header(info)

	samples := []probe.Sample{cold(1, 1, 30, 60, 30, 125), cold(2, 0, 31, 61, 31, 126)}
	for _, s := range samples {
		r.Sample(s)
	}
	r.Summary(stats.Compute(samples, time.Second, 0))

	got := out.String()
	if strings.Contains(got, "WARM") || strings.Contains(got, "wait") {
		t.Errorf("-m cold still drew the warm side:\n%s", got)
	}
	if strings.Contains(got, "keep-alive gain") {
		t.Error("-m cold printed keep-alive gain, which needs both modes")
	}
	if !strings.Contains(got, "handshake overhead") {
		t.Error("-m cold dropped handshake overhead, which needs only cold")
	}
}

func TestUnmeasuredPhaseRendersAsDash(t *testing.T) {
	if got := msCell(probe.Phase{}); got != "-" {
		t.Errorf("unmeasured phase = %q, want %q", got, "-")
	}
	if got := msCell(probe.Measured(0)); got != "0" {
		t.Errorf("measured zero = %q, want %q: 0ms is not the same as unmeasured", got, "0")
	}
	if got := msCell(probe.Measured(200 * time.Second)); got != ">99s" {
		t.Errorf("oversized phase = %q, want %q", got, ">99s")
	}
}

func TestNoColorProducesNoEscapes(t *testing.T) {
	out := renderFixture(t, Options{Width: 140, Layout: LayoutWide, Color: false})
	if strings.Contains(out, "\x1b[") {
		t.Error("ANSI escapes emitted although colour is off")
	}
}

func TestColorHighlightsFailure(t *testing.T) {
	out := renderFixture(t, Options{Width: 140, Layout: LayoutWide, Color: true})
	if !strings.Contains(out, ansiRed) {
		t.Error("the timed-out row is not marked red")
	}
}

func TestJSONSchema(t *testing.T) {
	var out, errw bytes.Buffer
	r := NewJSON(&out, &errw, "0.1.0")
	r.Header(testInfo())
	samples := fixture()
	for _, s := range samples {
		r.Sample(s)
	}
	r.Summary(stats.Compute(samples, 6200*time.Millisecond, 1))

	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if doc["schema"] != float64(SchemaVersion) {
		t.Errorf("schema = %v, want %d", doc["schema"], SchemaVersion)
	}

	arr, ok := doc["samples"].([]any)
	if !ok || len(arr) != len(samples) {
		t.Fatalf("samples = %T with %d entries, want %d", doc["samples"], len(arr), len(samples))
	}

	// A warm sample must serialise dns as null, not 0: the distinction is the
	// whole point of Phase.OK (PLAN §4.1).
	warmSample := arr[1].(map[string]any)
	if warmSample["mode"] != "warm" {
		t.Fatalf("second sample is %v, want warm", warmSample["mode"])
	}
	if warmSample["dns_ms"] != nil {
		t.Errorf("warm dns_ms = %v, want null", warmSample["dns_ms"])
	}
	if warmSample["wait_ms"] == nil {
		t.Error("warm wait_ms is null, want a measurement")
	}

	last := arr[len(arr)-2].(map[string]any)
	if last["error_kind"] != "timeout" {
		t.Errorf("failed sample error_kind = %v, want a stable timeout slug", last["error_kind"])
	}

	sum := doc["summary"].(map[string]any)
	if sum["handshake_overhead_ms"] == nil {
		t.Error("summary is missing handshake_overhead_ms")
	}
}

func TestCSVSchema(t *testing.T) {
	var out, errw bytes.Buffer
	r := NewCSV(&out, &errw)
	r.Header(testInfo())
	samples := fixture()
	for _, s := range samples {
		r.Sample(s)
	}
	r.Summary(stats.Compute(samples, time.Second, 1))

	rows, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) != len(samples)+1 {
		t.Fatalf("got %d rows, want %d samples plus a header", len(rows), len(samples))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Fatalf("header has %d columns, want %d", len(rows[0]), len(csvHeader))
	}
	for i, row := range rows[1:] {
		if len(row) != len(csvHeader) {
			t.Fatalf("row %d has %d fields, want %d", i, len(row), len(csvHeader))
		}
	}
	// warm row: dns must be empty rather than 0.
	dnsCol := indexOf(csvHeader, "dns_ms")
	if rows[2][dnsCol] != "" {
		t.Errorf("warm dns_ms = %q, want an empty field", rows[2][dnsCol])
	}
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

func TestRunningMedianHighlight(t *testing.T) {
	var m runningMedian
	for _, d := range []time.Duration{ms(100), ms(100), ms(100), ms(100)} {
		m.add(d)
	}
	if !m.slow(ms(200)) {
		t.Error("200ms not flagged against a 100ms median")
	}
	if m.slow(ms(140)) {
		t.Error("140ms flagged although it is below 1.5x the median")
	}

	var few runningMedian
	few.add(ms(10))
	if few.slow(ms(1000)) {
		t.Error("a single prior sample is not enough to call anything an outlier")
	}
}
