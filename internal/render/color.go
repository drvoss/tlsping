// Package render turns samples and summaries into terminal or machine output.
// It depends on probe and stats, never the other way round (PLAN §5.1).
package render

import (
	"os"
	"time"
)

// Palette applies ANSI colour when the destination can show it.
type Palette struct{ Enabled bool }

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
)

func (p Palette) wrap(code, s string) string {
	if !p.Enabled || s == "" {
		return s
	}
	return code + s + ansiReset
}

// Red marks failures and timeouts.
func (p Palette) Red(s string) string { return p.wrap(ansiRed, s) }

// Yellow marks a sample slower than 1.5x the running median.
func (p Palette) Yellow(s string) string { return p.wrap(ansiYellow, s) }

// Dim marks secondary annotations.
func (p Palette) Dim(s string) string { return p.wrap(ansiDim, s) }

// Bold marks headings.
func (p Palette) Bold(s string) string { return p.wrap(ansiBold, s) }

// ColorEnabled decides whether to emit ANSI at all: an explicit --no-color
// wins, then NO_COLOR, then whether stdout is actually a terminal (PLAN §2.3).
func ColorEnabled(noColor bool, f *os.File) bool {
	if noColor {
		return false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if !isTerminal(f) {
		return false
	}
	return enableVT(f)
}

// slowFactor is the multiple of the running median past which a sample is
// highlighted (PLAN §2.3).
const slowFactor = 1.5

// runningMedian tracks a median as samples stream in. The table is appended
// live, so the threshold can only ever be based on what has been seen so far.
type runningMedian struct{ sorted []time.Duration }

func (r *runningMedian) add(d time.Duration) {
	i := 0
	for i < len(r.sorted) && r.sorted[i] < d {
		i++
	}
	r.sorted = append(r.sorted, 0)
	copy(r.sorted[i+1:], r.sorted[i:])
	r.sorted[i] = d
}

func (r *runningMedian) median() (time.Duration, bool) {
	n := len(r.sorted)
	if n == 0 {
		return 0, false
	}
	if n%2 == 1 {
		return r.sorted[n/2], true
	}
	return (r.sorted[n/2-1] + r.sorted[n/2]) / 2, true
}

// slow reports whether d is far enough above the running median to highlight.
// A handful of samples is not enough to call anything an outlier.
func (r *runningMedian) slow(d time.Duration) bool {
	m, ok := r.median()
	if !ok || len(r.sorted) < 3 {
		return false
	}
	return float64(d) > slowFactor*float64(m)
}
