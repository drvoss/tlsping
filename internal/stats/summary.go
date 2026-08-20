package stats

import (
	"time"

	"github.com/drvoss/tlsping/internal/probe"
)

// Agg is the timing statistic for one mode.
type Agg struct {
	N        int // usable samples: warmup, failures and warm new-conn excluded
	Sent, OK int
	Loss     float64 // 0.0 - 1.0

	Min, Mean, Median, Max, Mdev time.Duration

	P95 probe.Phase // OK=false when n < MinP95Samples (PLAN §4.4)
}

// Summary is the whole run, and the contract render consumes (PLAN §5.3).
type Summary struct {
	Cold, Warm Agg

	NewConn int // warm samples that had to dial

	Overhead                              time.Duration // median of dns+tcp+tls per cold sample
	OverheadDNS, OverheadTCP, OverheadTLS time.Duration
	OverheadSkipped                       int // cold samples missing a phase, so excluded

	Gain       time.Duration // median(cold.total) - median(warm.total); may be negative
	PairedGain probe.Phase   // median of per-round (cold.total - warm.total), -v only

	Elapsed     time.Duration
	WarmupCount int

	Resumed  int // cold samples whose TLS handshake resumed a session
	ColdSeen int // cold samples considered, warmup excluded
}

// Compute folds samples into a Summary.
//
// The rules it encodes, all from PLAN §4.4: warmup rounds leave both modes;
// a response of any status counts as ok; a warm sample that had to dial is ok
// but excluded from timings; handshake overhead is summed inside a single
// sample rather than across distributions.
func Compute(samples []probe.Sample, elapsed time.Duration, warmup int) Summary {
	sum := Summary{Elapsed: elapsed, WarmupCount: warmup}

	var coldTotals, warmTotals []time.Duration
	var ohTotal, ohDNS, ohTCP, ohTLS []time.Duration
	coldByRound := map[int]time.Duration{}
	warmByRound := map[int]time.Duration{}

	for _, s := range samples {
		if s.IsWarmup {
			continue
		}
		agg := &sum.Cold
		if s.Mode == probe.Warm {
			agg = &sum.Warm
		}
		agg.Sent++
		if s.Responded() {
			agg.OK++
		}

		if s.NewConn() {
			sum.NewConn++
		}
		if s.Mode == probe.Cold {
			sum.ColdSeen++
			if s.Resumed {
				sum.Resumed++
			}
		}

		if !s.Timed() {
			continue
		}
		if s.Mode == probe.Cold {
			coldTotals = append(coldTotals, s.Total.D)
			coldByRound[s.Round] = s.Total.D

			// Every phase that applies must be measured, otherwise the sum
			// would silently understate the handshake (PLAN §4.4).
			if total, ok := s.HandshakeSum(); ok {
				ohTotal = append(ohTotal, total)
				ohDNS = append(ohDNS, s.DNS.D)
				ohTCP = append(ohTCP, s.TCP.D)
				if s.TLS.OK {
					ohTLS = append(ohTLS, s.TLS.D)
				}
			} else {
				sum.OverheadSkipped++
			}
		} else {
			warmTotals = append(warmTotals, s.Total.D)
			warmByRound[s.Round] = s.Total.D
		}
	}

	sum.Cold = fill(sum.Cold, coldTotals)
	sum.Warm = fill(sum.Warm, warmTotals)

	sum.Overhead = Median(ohTotal)
	sum.OverheadDNS = Median(ohDNS)
	sum.OverheadTCP = Median(ohTCP)
	sum.OverheadTLS = Median(ohTLS)

	// Subtracting two medians drawn from different distributions is not a
	// statistic; it is printed only as a reference figure (PLAN §1.2, §4.4).
	if len(coldTotals) > 0 && len(warmTotals) > 0 {
		sum.Gain = Median(coldTotals) - Median(warmTotals)
	}

	// The paired difference is the defensible version: same round, same time
	// window, so the confounders cancel.
	var paired []time.Duration
	for round, c := range coldByRound {
		if w, ok := warmByRound[round]; ok {
			paired = append(paired, c-w)
		}
	}
	if len(paired) > 0 {
		sum.PairedGain = probe.Measured(Median(paired))
	}

	return sum
}

// fill completes an Agg whose Sent/OK counters are already set.
func fill(a Agg, values []time.Duration) Agg {
	if a.Sent > 0 {
		a.Loss = float64(a.Sent-a.OK) / float64(a.Sent)
	}
	a.N = len(values)
	if a.N == 0 {
		return a
	}
	a.Min, a.Max = MinMax(values)
	a.Mean = Mean(values)
	a.Median = Median(values)
	a.Mdev = Mdev(values)
	if a.N >= MinP95Samples {
		a.P95 = probe.Measured(Percentile(sortedCopy(values), 95))
	}
	return a
}
