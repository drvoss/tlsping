package render

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/drvoss/tlsping/internal/probe"
	"github.com/drvoss/tlsping/internal/stats"
)

// Renderer is the contract between the runner and the output. render owns it:
// putting it in probe would drag stats.Summary into probe and create a cycle
// (PLAN §5.3).
//
// Sample is called once per probe as it completes. Implementations that print
// one line per round are responsible for joining the cold and warm samples that
// share a Round number.
type Renderer interface {
	Header(probe.RunInfo)  // once, right after the preflight
	Sample(probe.Sample)   // once per probe
	Warn(msg string)       // stderr: rate-limit stops, oversized other, ...
	Summary(stats.Summary) // once, at the end
}

// Options configure a renderer. main builds this from the CLI config, so render
// never has to import cli.
type Options struct {
	Verbose bool
	Quiet   bool
	// Color and ErrColor are decided per stream: stdout can be a terminal while
	// stderr is redirected to a file, and a shared flag would write raw escape
	// codes into that file.
	Color    bool
	ErrColor bool
	Width    int
	Layout   Layout
}

// Failer is implemented by renderers that can report a write failure. main
// checks for it so that a truncated or undeliverable result is not reported as
// a success.
type Failer interface{ Err() error }

// Fixed cell geometry. The table is appended live, so a future maximum cannot
// be known and the widths cannot adapt (PLAN §2.3).
const (
	cellW  = 6 // " 12345"
	idxW   = 4
	coldW  = 5 * cellW // dns tcp tls srv total
	warmW  = 3 * cellW // wait srv total
	codeW  = 7
	maxCol = 99999 // milliseconds that still fit; beyond this we abbreviate
)

// TableRenderer prints the human-facing table (PLAN §2.1, §2.2).
type TableRenderer struct {
	out    *errWriter
	errw   io.Writer
	pal    Palette
	errPal Palette
	opt    Options

	info    probe.RunInfo
	pending map[int][]probe.Sample
	buf     []probe.Sample // LayoutMin defers every row until Summary

	coldMed, warmMed runningMedian
	chainLen         int // peer certificate count, from the last real handshake
}

// errWriter remembers the first write failure. A broken pipe or a full disk
// must not let a truncated result be reported as a success.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// NewTable builds the default renderer.
func NewTable(out, errw io.Writer, opt Options) *TableRenderer {
	return &TableRenderer{
		out:     &errWriter{w: out},
		errw:    errw,
		pal:     Palette{Enabled: opt.Color},
		errPal:  Palette{Enabled: opt.ErrColor},
		opt:     opt,
		pending: map[int][]probe.Sample{},
	}
}

// Err reports the first failure writing the report, if any.
func (t *TableRenderer) Err() error { return t.out.err }

func (t *TableRenderer) Header(info probe.RunInfo) {
	t.info = info

	var meta []string
	if info.Proto != "" {
		meta = append(meta, info.Proto)
	}
	if info.TLSVer != "" {
		meta = append(meta, info.TLSVer)
	}
	meta = append(meta, fmt.Sprintf("%d bytes", info.Bytes))

	fmt.Fprintln(t.out)
	if t.narrow() {
		// One long line would wrap and ruin the alignment the fallback exists
		// to protect, so the target is split across lines.
		fmt.Fprintf(t.out, "%s %s\n", info.Method, info.URL)
		fmt.Fprintf(t.out, "  -> %s  %s\n", info.Addr, strings.Join(meta, " · "))
	} else {
		fmt.Fprintf(t.out, "%s %s -> %s   %s\n", info.Method, info.URL, info.Addr, strings.Join(meta, " · "))
	}

	rounds := "unlimited rounds"
	if info.Count > 0 {
		rounds = fmt.Sprintf("%d rounds", info.Count)
	}
	fmt.Fprintf(t.out, "%s, %s interval, order=%s", rounds, short(info.Interval), info.Order)
	if info.Mode != probe.Both {
		fmt.Fprintf(t.out, ", mode=%s", info.Mode)
	}
	// The unit is stated once here rather than repeated per column (PLAN §2.3).
	if t.narrow() {
		fmt.Fprintln(t.out)
		fmt.Fprintln(t.out, `times in ms, "-" = not measured`)
	} else {
		fmt.Fprintln(t.out, `; all times in ms, "-" = not measured`)
	}

	// With -m warm nothing ever resolves during a round, so the only DNS figure
	// available is the preflight's (PLAN §4.2).
	if info.Mode == probe.WarmOnly && info.DNSFirst.OK {
		fmt.Fprintf(t.out, "dns (preflight) %s\n", short(info.DNSFirst.D))
	}
	if !info.Pinned {
		fmt.Fprintln(t.out, "ip pinning off")
	}
	fmt.Fprintln(t.out)

	if t.opt.Layout == LayoutWide {
		t.writeWideHead()
	}
}

func (t *TableRenderer) Warn(msg string) {
	fmt.Fprintln(t.errw, t.errPal.Yellow("tlsping: "+msg))
}

func (t *TableRenderer) Sample(s probe.Sample) {
	t.track(s)
	if s.ChainLen > 0 {
		t.chainLen = s.ChainLen
	}

	if t.opt.Layout == LayoutMin {
		t.buf = append(t.buf, s)
		return
	}

	t.pending[s.Round] = append(t.pending[s.Round], s)
	if len(t.pending[s.Round]) < t.perRound() {
		return
	}
	round := t.pending[s.Round]
	delete(t.pending, s.Round)
	t.emit(round)
}

// track feeds the running medians that drive the slow-sample highlight.
func (t *TableRenderer) track(s probe.Sample) {
	if !s.Timed() {
		return
	}
	if s.Mode == probe.Cold {
		t.coldMed.add(s.Total.D)
	} else {
		t.warmMed.add(s.Total.D)
	}
}

// perRound is how many samples make one complete row.
func (t *TableRenderer) perRound() int {
	if t.info.Mode == probe.Both {
		return 2
	}
	return 1
}

func (t *TableRenderer) emit(round []probe.Sample) {
	switch t.opt.Layout {
	case LayoutMid:
		t.writeMidRow(round)
	default:
		t.writeWideRow(round)
	}
}

// pick returns the sample of the given mode from a round, if present.
func pick(round []probe.Sample, mode probe.Mode) (probe.Sample, bool) {
	for _, s := range round {
		if s.Mode == mode {
			return s, true
		}
	}
	return probe.Sample{}, false
}

// ---------------------------------------------------------------- wide layout

func (t *TableRenderer) writeWideHead() {
	cold, warm := t.info.Mode.HasCold(), t.info.Mode.HasWarm()

	var l1, l2, sep strings.Builder
	l1.WriteString(strings.Repeat(" ", idxW+1) + "|")
	l2.WriteString(strings.Repeat(" ", idxW+1) + "|")
	sep.WriteString(strings.Repeat("-", idxW+1) + "+")

	if cold {
		if t.opt.Quiet {
			l1.WriteString(pad("  COLD", cellW) + " |")
			l2.WriteString(fmt.Sprintf("%*s", cellW, "total") + " |")
			sep.WriteString(strings.Repeat("-", cellW) + "-+")
		} else {
			l1.WriteString(pad("  COLD  new connection", coldW) + " |")
			for _, h := range []string{"dns", "tcp", "tls", "srv", "total"} {
				fmt.Fprintf(&l2, "%*s", cellW, h)
			}
			l2.WriteString(" |")
			sep.WriteString(strings.Repeat("-", coldW) + "-+")
		}
	}
	if warm {
		if t.opt.Quiet {
			l1.WriteString(pad("  WARM", cellW) + " |")
			l2.WriteString(fmt.Sprintf("%*s", cellW, "total") + " |")
			sep.WriteString(strings.Repeat("-", cellW) + "-+")
		} else {
			l1.WriteString(pad("  WARM  keep-alive", warmW) + " |")
			for _, h := range []string{"wait", "srv", "total"} {
				fmt.Fprintf(&l2, "%*s", cellW, h)
			}
			l2.WriteString(" |")
			sep.WriteString(strings.Repeat("-", warmW) + "-+")
		}
	}
	l2.WriteString(" code")
	sep.WriteString(strings.Repeat("-", codeW))

	// l1 keeps its trailing bar so that every line of the grid, header included,
	// puts its separators in the same columns.
	fmt.Fprintln(t.out, strings.TrimRight(l1.String(), " "))
	fmt.Fprintln(t.out, l2.String())
	fmt.Fprintln(t.out, sep.String())
}

// narrow reports whether the layout has a hard column budget to respect.
func (t *TableRenderer) narrow() bool { return t.opt.Layout != LayoutWide }

func (t *TableRenderer) writeWideRow(round []probe.Sample) {
	var b strings.Builder
	fmt.Fprintf(&b, "%*d |", idxW, round[0].Round)

	if t.info.Mode.HasCold() {
		s, ok := pick(round, probe.Cold)
		b.WriteString(t.section(s, ok, probe.Cold))
		b.WriteString(" |")
	}
	if t.info.Mode.HasWarm() {
		s, ok := pick(round, probe.Warm)
		b.WriteString(t.section(s, ok, probe.Warm))
		b.WriteString(" |")
	}

	fmt.Fprintf(&b, " %-*s", codeW, t.codeCell(round))
	if notes := t.notes(round); notes != "" {
		b.WriteString("  " + t.pal.Dim(notes))
	}
	fmt.Fprintln(t.out, strings.TrimRight(b.String(), " "))
}

// section renders one mode's cells, or a centred reason when it failed.
func (t *TableRenderer) section(s probe.Sample, ok bool, mode probe.Mode) string {
	width := coldW
	if mode == probe.Warm {
		width = warmW
	}
	if t.opt.Quiet {
		width = cellW
	}

	if !ok {
		return strings.Repeat(" ", width)
	}
	if s.Err != nil {
		// A quiet cell is six columns wide, which would chop "timeout (5s)" into
		// something indistinguishable from a truncated number. Leave the cell
		// empty there and let the row note carry the reason.
		if t.opt.Quiet {
			return t.pal.Red(fmt.Sprintf("%*s", width, "err"))
		}
		return t.pal.Red(center(t.reasonText(s), width))
	}

	med := &t.coldMed
	if mode == probe.Warm {
		med = &t.warmMed
	}
	slow := s.Total.OK && med.slow(s.Total.D)

	var phases []probe.Phase
	switch {
	case t.opt.Quiet:
		phases = []probe.Phase{s.Total}
	case mode == probe.Cold:
		phases = []probe.Phase{s.DNS, s.TCP, s.TLS, s.Srv, s.Total}
	default:
		phases = []probe.Phase{s.Wait, s.Srv, s.Total}
	}

	var b strings.Builder
	for i, p := range phases {
		cell := fmt.Sprintf("%*s", cellW, msCell(p))
		// Only the total is highlighted: it is the figure the eye compares.
		if slow && i == len(phases)-1 {
			cell = t.pal.Yellow(cell)
		}
		b.WriteString(cell)
	}
	return b.String()
}

// reasonText is the failure cell. A timeout carries the configured limit,
// because "timeout" alone does not say how long the tool waited (PLAN §2.3).
func (t *TableRenderer) reasonText(s probe.Sample) string {
	r := probe.Reason(s.Err)
	if s.Kind() == probe.ErrTimeout && t.info.Timeout > 0 {
		r += fmt.Sprintf(" (%s)", short(t.info.Timeout))
	}
	return r
}

// codeCell shows one status when both modes agree, otherwise cold/warm with "-"
// standing for a mode that never got a response (PLAN §2.3).
func (t *TableRenderer) codeCell(round []probe.Sample) string {
	cold, hasCold := pick(round, probe.Cold)
	warm, hasWarm := pick(round, probe.Warm)

	switch {
	case hasCold && hasWarm:
		if cold.Status == warm.Status && cold.Status != 0 {
			return statusText(cold.Status)
		}
		return statusText(cold.Status) + "/" + statusText(warm.Status)
	case hasCold:
		return statusText(cold.Status)
	case hasWarm:
		return statusText(warm.Status)
	}
	return "-"
}

// notes builds the trailing annotations. Modes are visited in a fixed order so
// that the same run always reads the same way, whatever order the round used.
func (t *TableRenderer) notes(round []probe.Sample) string {
	ordered := make([]probe.Sample, 0, len(round))
	for _, mode := range []probe.Mode{probe.Cold, probe.Warm} {
		if s, ok := pick(round, mode); ok {
			ordered = append(ordered, s)
		}
	}

	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, s := range ordered {
		for _, n := range s.Note() {
			add(n)
		}
		// In quiet mode the cell has no room for the reason, so it lives here.
		if t.opt.Quiet && s.Err != nil {
			add(fmt.Sprintf("%s %s", s.Mode, t.reasonText(s)))
		}
	}
	if t.opt.Verbose {
		for _, s := range ordered {
			if s.Resumed {
				add("tls resumed")
			}
			if s.Other.OK {
				add(fmt.Sprintf("%s other %s", s.Mode, short(s.Other.D)))
			}
		}
	}
	return strings.Join(out, "·")
}

// ----------------------------------------------------------------- mid layout

func (t *TableRenderer) writeMidRow(round []probe.Sample) {
	for _, mode := range []probe.Mode{probe.Cold, probe.Warm} {
		s, ok := pick(round, mode)
		if !ok {
			continue
		}
		prefix := strings.Repeat(" ", 6)
		if mode == probe.Cold || !t.info.Mode.HasCold() {
			prefix = fmt.Sprintf("  #%-3d", s.Round)
		}
		fmt.Fprintln(t.out, t.midLine(s, prefix))
		// Annotations get their own line: appending them would push the row
		// past the width that selected this layout.
		if notes := strings.Join(s.Note(), "·"); notes != "" {
			fmt.Fprintf(t.out, "%s%s\n", strings.Repeat(" ", midNoteIndent), t.pal.Dim(notes))
		}
	}
}

// midFieldW is the width labelled() produces: a four-character label followed
// by a four-character right-aligned value.
const midFieldW = 8

// midNoteIndent lines annotations up under the phase fields.
const midNoteIndent = 12

func (t *TableRenderer) midLine(s probe.Sample, prefix string) string {
	label := strings.ToUpper(s.Mode.String())
	if s.Err != nil {
		return t.pal.Red(fmt.Sprintf("%s %s  %s", prefix, label, t.reasonText(s)))
	}

	// Label and value are always separated by a space so that "dns 0" can never
	// read as "dns0" (PLAN §2.2).
	var fields []string
	if s.Mode == probe.Cold {
		fields = []string{
			labelled("dns", s.DNS), labelled("tcp", s.TCP),
			labelled("tls", s.TLS), labelled("srv", s.Srv),
		}
	} else {
		// Two blank fields keep warm's srv under cold's srv.
		blank := strings.Repeat(" ", midFieldW)
		fields = []string{labelled("wait", s.Wait), blank, blank, labelled("srv", s.Srv)}
	}

	total := fmt.Sprintf("= %5sms", msCell(s.Total))
	if t.slowFor(s) {
		total = t.pal.Yellow(total)
	}
	line := fmt.Sprintf("%s %s %s %s %s",
		prefix, label, strings.Join(fields, " "), total, statusText(s.Status))
	return strings.TrimRight(line, " ")
}

func (t *TableRenderer) slowFor(s probe.Sample) bool {
	if !s.Total.OK {
		return false
	}
	if s.Mode == probe.Cold {
		return t.coldMed.slow(s.Total.D)
	}
	return t.warmMed.slow(s.Total.D)
}

// ------------------------------------------------------------- minimal layout

// flushMin prints the whole cold block, then the whole warm block. Live append
// is impossible here, so rows are held until the end (PLAN §2.2).
func (t *TableRenderer) flushMin() {
	for _, mode := range []probe.Mode{probe.Cold, probe.Warm} {
		if mode == probe.Cold && !t.info.Mode.HasCold() {
			continue
		}
		if mode == probe.Warm && !t.info.Mode.HasWarm() {
			continue
		}
		fmt.Fprintf(t.out, "%s\n", strings.ToUpper(mode.String()))
		for _, s := range t.buf {
			if s.Mode != mode {
				continue
			}
			fmt.Fprintln(t.out, t.minLine(s))
		}
		fmt.Fprintln(t.out)
	}
}

func (t *TableRenderer) minLine(s probe.Sample) string {
	if s.Err != nil {
		return t.pal.Red(fmt.Sprintf("%*d  %s", idxW, s.Round, t.reasonText(s)))
	}
	var parts []string
	if s.Mode == probe.Cold {
		parts = []string{labelled("dns", s.DNS), labelled("tcp", s.TCP), labelled("tls", s.TLS)}
	} else {
		parts = []string{labelled("wait", s.Wait)}
	}
	parts = append(parts, labelled("srv", s.Srv), "= "+msCell(s.Total)+"ms", statusText(s.Status))
	line := fmt.Sprintf("%*d %s", idxW, s.Round, strings.Join(parts, " "))
	if notes := strings.Join(s.Note(), "·"); notes != "" {
		line += "\n" + strings.Repeat(" ", idxW+1) + t.pal.Dim(notes)
	}
	return line
}

// ----------------------------------------------------------------- formatting

// msCell renders a phase for a fixed-width column: "-" when unmeasured, and
// abbreviated once it no longer fits (PLAN §2.3).
func msCell(p probe.Phase) string {
	if !p.OK {
		return "-"
	}
	ms := p.D.Milliseconds()
	if ms > maxCol {
		return ">99s"
	}
	if ms < 0 {
		return "-"
	}
	return fmt.Sprintf("%d", ms)
}

// labelled renders "dns   12" with a fixed label and value width so that the
// same phase lines up across rows in the narrow layouts.
func labelled(name string, p probe.Phase) string {
	return fmt.Sprintf("%-4s%4s", name, msCell(p))
}

func statusText(code int) string {
	if code == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", code)
}

// The column grid is counted in terminal cells, which are runes, not bytes.
// Measuring with len() would let a single multi-byte character (a header
// separator, a localised error string) shift every bar on the row.

func cells(s string) int { return utf8.RuneCountInString(s) }

// cut shortens s to w cells, marking the cut with an ASCII '~' so a shortened
// reason can never be mistaken for the whole reason.
func cut(s string, w int) string {
	if cells(s) <= w {
		return s
	}
	r := []rune(s)
	if w <= 1 {
		return string(r[:w])
	}
	return string(r[:w-1]) + "~"
}

func pad(s string, w int) string {
	s = cut(s, w)
	return s + strings.Repeat(" ", w-cells(s))
}

func center(s string, w int) string {
	s = cut(s, w)
	left := (w - cells(s)) / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", w-cells(s)-left)
}

// short formats a duration compactly for headers and notes.
func short(d time.Duration) string {
	switch {
	case d >= time.Second:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", d.Seconds()), ".0") + "s"
	case d >= time.Millisecond:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d <= 0:
		return "0ms"
	default:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	}
}
