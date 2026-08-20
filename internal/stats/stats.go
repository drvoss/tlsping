// Package stats aggregates probe samples. It depends on probe and nothing
// else in the tree (PLAN §5.1).
package stats

import (
	"math"
	"sort"
	"time"
)

// MinP95Samples is the sample count below which p95 is not reported. With a
// handful of samples the 95th percentile is just the maximum, which carries no
// information (PLAN §4.4).
const MinP95Samples = 20

// sortedCopy returns d sorted ascending, leaving the caller's slice alone.
func sortedCopy(d []time.Duration) []time.Duration {
	out := make([]time.Duration, len(d))
	copy(out, d)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Percentile returns the nearest-rank percentile of sorted, with no
// interpolation (PLAN §4.4). p is in 0..100.
func Percentile(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// Median is the usual median: the middle value, or the mean of the two middle
// values for an even count.
func Median(values []time.Duration) time.Duration {
	n := len(values)
	if n == 0 {
		return 0
	}
	s := sortedCopy(values)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Mean is the arithmetic mean.
func Mean(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += float64(v)
	}
	return time.Duration(sum / float64(len(values)))
}

// Mdev is the population standard deviation, matching what iputils ping prints
// as mdev despite the name suggesting mean deviation (PLAN §4.4).
//
// The definition is sqrt(sum(x^2)/n - (sum(x)/n)^2), but that form is computed
// here in two passes. Nanosecond magnitudes squared land near the limit of
// float64 precision, and subtracting two large nearly equal numbers there loses
// exactly the small variance we are trying to report.
func Mdev(values []time.Duration) time.Duration {
	n := len(values)
	if n == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += float64(v)
	}
	mean := sum / float64(n)

	var sumSqDev float64
	for _, v := range values {
		d := float64(v) - mean
		sumSqDev += d * d
	}
	return time.Duration(math.Sqrt(sumSqDev / float64(n)))
}

// MinMax returns the extremes.
func MinMax(values []time.Duration) (time.Duration, time.Duration) {
	if len(values) == 0 {
		return 0, 0
	}
	lo, hi := values[0], values[0]
	for _, v := range values[1:] {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	return lo, hi
}
