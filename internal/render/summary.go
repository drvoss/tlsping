package render

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/drvoss/tlsping/internal/probe"
	"github.com/drvoss/tlsping/internal/stats"
)

func (t *TableRenderer) Summary(s stats.Summary) {
	t.flushPending()
	if t.opt.Layout == LayoutMin {
		t.flushMin()
		t.summaryVertical(s)
		return
	}
	t.summaryColumns(s)
}

// flushPending prints rounds that never completed. A run stopped by Ctrl+C, a
// 429 or the consecutive-failure guard can end between the cold and the warm
// probe, leaving a sample buffered while it waits for its partner. Dropping it
// would break the promise that no collected sample is lost.
func (t *TableRenderer) flushPending() {
	if len(t.pending) == 0 {
		return
	}
	rounds := make([]int, 0, len(t.pending))
	for r := range t.pending {
		rounds = append(rounds, r)
	}
	sort.Ints(rounds)
	for _, r := range rounds {
		t.emit(t.pending[r])
		delete(t.pending, r)
	}
}

// summaryColumns is the two-column statistics block from PLAN §2.1.
func (t *TableRenderer) summaryColumns(s stats.Summary) {
	cold, warm := t.info.Mode.HasCold(), t.info.Mode.HasWarm()

	fmt.Fprintf(t.out, "\n--- %s  statistics ---\n", t.info.Host)
	fmt.Fprintf(t.out, "  n = %s, elapsed %s\n", t.nText(s), short(s.Elapsed))

	head := "  " + pad("", 16)
	if cold {
		head += fmt.Sprintf("%10s  ", "cold")
	}
	if warm {
		head += fmt.Sprintf("%10s", "warm")
	}
	fmt.Fprintln(t.out, strings.TrimRight(head, " "))

	row := func(label string, f func(stats.Agg) string) {
		line := "  " + pad(label, 16)
		if cold {
			line += fmt.Sprintf("%10s  ", f(s.Cold))
		}
		if warm {
			line += fmt.Sprintf("%10s", f(s.Warm))
		}
		fmt.Fprintln(t.out, strings.TrimRight(line, " "))
	}

	row("ok / sent", func(a stats.Agg) string { return fmt.Sprintf("%d/%d", a.OK, a.Sent) })
	row("loss", func(a stats.Agg) string { return fmt.Sprintf("%.1f%%", a.Loss*100) })
	row("min", func(a stats.Agg) string { return aggDur(a, a.Min) })
	row("mean", func(a stats.Agg) string { return aggDur(a, a.Mean) })
	row("median", func(a stats.Agg) string { return aggDur(a, a.Median) })
	row("max", func(a stats.Agg) string { return aggDur(a, a.Max) })
	row("mdev", func(a stats.Agg) string { return aggDur(a, a.Mdev) })
	row("p95", func(a stats.Agg) string {
		if !a.P95.OK {
			return "-"
		}
		return short(a.P95.D)
	})

	if !s.Cold.P95.OK && !s.Warm.P95.OK {
		fmt.Fprintf(t.out, "  %s\n", t.pal.Dim(fmt.Sprintf("(p95 needs n >= %d)", stats.MinP95Samples)))
	}

	t.summaryDerived(s)
}

// summaryDerived prints the two headline figures and, crucially, labels which
// one is a real statistic and which one is only a reference (PLAN §2.1).
func (t *TableRenderer) summaryDerived(s stats.Summary) {
	fmt.Fprintln(t.out)

	if t.info.Mode.HasCold() && s.Cold.N > 0 {
		// A sum of durations, so it can never be negative: always "+".
		if t.narrow() {
			fmt.Fprintf(t.out, "  handshake overhead  +%s\n", short(s.Overhead))
		} else {
			fmt.Fprintf(t.out, "  handshake overhead  =  +%-7s median(dns+tcp+tls) per cold sample\n", short(s.Overhead))
		}
		// Per-stage medians, which need not add up to the median above: the
		// median of a sum is not the sum of the medians.
		fmt.Fprintf(t.out, "    dns %s · tcp %s · tls %s  (per-stage medians)\n",
			short(s.OverheadDNS), short(s.OverheadTCP), short(s.OverheadTLS))
		if s.OverheadSkipped > 0 && t.opt.Verbose {
			fmt.Fprintf(t.out, "    %s\n",
				t.pal.Dim(fmt.Sprintf("%d cold sample(s) excluded: a phase was not measured", s.OverheadSkipped)))
		}
	}

	if t.info.Mode == probe.Both && s.Cold.N > 0 && s.Warm.N > 0 {
		line := fmt.Sprintf("  keep-alive gain     =  %-8s median(cold.total) - median(warm.total)  [reference]", signed(s.Gain))
		if t.narrow() {
			line = fmt.Sprintf("  keep-alive gain     %s  [reference]", signed(s.Gain))
		}
		if s.Gain < 0 {
			// Negative means warm was slower than cold, which should not happen
			// if the order alternation cancelled the bias (PLAN §2.1).
			fmt.Fprintln(t.out, t.pal.Yellow(line))
			fmt.Fprintln(t.errw, t.errPal.Yellow("tlsping: keep-alive gain is negative — warm measured slower than cold; suspect server-side cache warming or uncancelled order bias"))
		} else {
			fmt.Fprintln(t.out, line)
		}
		if t.opt.Verbose && s.PairedGain.OK {
			// The paired median is the defensible figure: same round, same time
			// window, so confounders cancel (PLAN §4.4).
			fmt.Fprintf(t.out, "    paired %s  median of per-round (cold.total - warm.total)\n",
				signed(s.PairedGain.D))
		}
	}

	// Warm timings exclude every probe that had to dial, so a run where the
	// server keeps dropping the connection would otherwise show a flattering
	// warm median with nothing to explain it. Surface the count whenever it is
	// non-zero, not only under -v (PLAN §4.4).
	if !t.opt.Verbose && t.info.Mode.HasWarm() && s.NewConn > 0 {
		fmt.Fprintf(t.out, "\n  new conn            =  %d of %d warm probes had to dial and are excluded from the\n", s.NewConn, s.Warm.Sent)
		fmt.Fprintln(t.out, "                         warm timings — the server is not holding the connection open")
	}

	if t.opt.Verbose {
		t.verboseTail(s)
	}
}

func (t *TableRenderer) verboseTail(s stats.Summary) {
	fmt.Fprintln(t.out)
	if t.info.Mode.HasWarm() {
		fmt.Fprintf(t.out, "  new conn            =  %d  warm probes that had to dial\n", s.NewConn)
		if s.NewConn > 0 {
			fmt.Fprintln(t.out, "                         a non-zero count means the server is not holding the connection open")
		}
	}
	if t.info.Mode.HasCold() && s.ColdSeen > 0 {
		fmt.Fprintf(t.out, "  tls resumed         =  %d/%d cold handshakes\n", s.Resumed, s.ColdSeen)
		fmt.Fprintln(t.out, "                         a resumed handshake is shorter, so tls after the first")
		fmt.Fprintln(t.out, "                         round is not a full first-contact handshake")
	}
	if t.chainLen > 0 {
		fmt.Fprintf(t.out, "  cert chain          =  %d certificate(s)\n", t.chainLen)
	}
	if t.info.TLSVer != "" {
		fmt.Fprintf(t.out, "  tls version         =  %s\n", t.info.TLSVer)
	}
	if s.OverheadSkipped > 0 {
		fmt.Fprintf(t.out, "  overhead excluded   =  %d cold sample(s)\n", s.OverheadSkipped)
	}
	if t.info.ALPN != "" {
		fmt.Fprintf(t.out, "  alpn                =  %s\n", t.info.ALPN)
	}
	if t.info.Proto == "h2" {
		fmt.Fprintln(t.out, "  note                =  on HTTP/2, Reused means a new stream on an existing connection, not an exclusive connection")
	}
}

// summaryVertical is the narrow-terminal form: one figure per line (PLAN §2.2).
func (t *TableRenderer) summaryVertical(s stats.Summary) {
	fmt.Fprintf(t.out, "--- %s statistics ---\n", t.info.Host)
	fmt.Fprintf(t.out, "n = %s, elapsed %s\n", t.nText(s), short(s.Elapsed))

	show := func(name string, a stats.Agg) {
		fmt.Fprintf(t.out, "\n%s\n", name)
		fmt.Fprintf(t.out, "  ok/sent  %d/%d\n", a.OK, a.Sent)
		fmt.Fprintf(t.out, "  loss     %.1f%%\n", a.Loss*100)
		fmt.Fprintf(t.out, "  min      %s\n", aggDur(a, a.Min))
		fmt.Fprintf(t.out, "  mean     %s\n", aggDur(a, a.Mean))
		fmt.Fprintf(t.out, "  median   %s\n", aggDur(a, a.Median))
		fmt.Fprintf(t.out, "  max      %s\n", aggDur(a, a.Max))
		fmt.Fprintf(t.out, "  mdev     %s\n", aggDur(a, a.Mdev))
		if a.P95.OK {
			fmt.Fprintf(t.out, "  p95      %s\n", short(a.P95.D))
		} else {
			fmt.Fprintf(t.out, "  p95      -  (n < %d)\n", stats.MinP95Samples)
		}
	}
	if t.info.Mode.HasCold() {
		show("cold", s.Cold)
	}
	if t.info.Mode.HasWarm() {
		show("warm", s.Warm)
	}

	fmt.Fprintln(t.out)
	if t.info.Mode.HasCold() && s.Cold.N > 0 {
		fmt.Fprintf(t.out, "handshake overhead  +%s\n", short(s.Overhead))
		fmt.Fprintf(t.out, "  dns %s · tcp %s · tls %s\n", short(s.OverheadDNS), short(s.OverheadTCP), short(s.OverheadTLS))
	}
	if t.info.Mode == probe.Both && s.Cold.N > 0 && s.Warm.N > 0 {
		fmt.Fprintf(t.out, "keep-alive gain     %s  [reference]\n", signed(s.Gain))
	}
}

func (t *TableRenderer) nText(s stats.Summary) string {
	n := s.Cold.N
	if !t.info.Mode.HasCold() {
		n = s.Warm.N
	}
	if s.WarmupCount > 0 {
		return fmt.Sprintf("%d (warmup %d excluded)", n, s.WarmupCount)
	}
	return fmt.Sprintf("%d", n)
}

// aggDur hides a duration when there was no usable sample, so an empty run
// prints "-" rather than a misleading 0ms.
func aggDur(a stats.Agg, d time.Duration) string {
	if a.N == 0 {
		return "-"
	}
	return short(d)
}

func signed(d time.Duration) string {
	if d < 0 {
		return "-" + short(-d)
	}
	return "+" + short(d)
}
