package stats

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/drvoss/tlsping/internal/probe"
)

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func durs(ns ...int) []time.Duration {
	out := make([]time.Duration, len(ns))
	for i, n := range ns {
		out[i] = ms(n)
	}
	return out
}

func TestPercentileNearestRank(t *testing.T) {
	// nearest-rank: rank = ceil(p/100*n), no interpolation (PLAN §4.4).
	s := durs(10, 20, 30, 40, 50, 60, 70, 80, 90, 100)
	cases := []struct {
		p    float64
		want time.Duration
	}{
		{0, ms(10)},   // clamped to rank 1
		{1, ms(10)},   // ceil(0.1) = 1
		{10, ms(10)},  // ceil(1) = 1
		{11, ms(20)},  // ceil(1.1) = 2
		{50, ms(50)},  // ceil(5) = 5
		{95, ms(100)}, // ceil(9.5) = 10
		{100, ms(100)},
	}
	for _, c := range cases {
		if got := Percentile(s, c.p); got != c.want {
			t.Errorf("Percentile(p=%v) = %v, want %v", c.p, got, c.want)
		}
	}
	if got := Percentile(nil, 95); got != 0 {
		t.Errorf("Percentile of empty = %v, want 0", got)
	}
}

func TestMedian(t *testing.T) {
	if got := Median(durs(3, 1, 2)); got != ms(2) {
		t.Errorf("odd median = %v, want 2ms", got)
	}
	if got := Median(durs(4, 1, 3, 2)); got != ms(2)+ms(1)/2 {
		t.Errorf("even median = %v, want 2.5ms", got)
	}
	if got := Median(nil); got != 0 {
		t.Errorf("empty median = %v, want 0", got)
	}
	in := durs(3, 1, 2)
	_ = Median(in)
	if in[0] != ms(3) {
		t.Error("Median reordered the caller's slice")
	}
}

func TestMdevIsPopulationStdDev(t *testing.T) {
	// Population stddev of {2,4,4,4,5,5,7,9} is exactly 2.
	if got := Mdev(durs(2, 4, 4, 4, 5, 5, 7, 9)); got != ms(2) {
		t.Errorf("Mdev = %v, want 2ms", got)
	}
	if got := Mdev(durs(5, 5, 5, 5)); got != 0 {
		t.Errorf("Mdev of a constant series = %v, want 0", got)
	}
	if got := Mdev(nil); got != 0 {
		t.Errorf("Mdev of empty = %v, want 0", got)
	}

	// A mean/max/n combination bounds mdev from below; this is the arithmetic
	// that caught a bad mock-up in PLAN §11 round 6.
	vals := durs(128, 130, 133, 140, 140, 142, 145, 148, 151)
	mean, max := Mean(vals), ms(151)
	lower := math.Abs(float64(max-mean)) / math.Sqrt(float64(len(vals)))
	if float64(Mdev(vals)) < lower-1 {
		t.Errorf("Mdev %v below the arithmetic floor %v", Mdev(vals), time.Duration(lower))
	}
}

func sample(round int, mode probe.Mode, total int, opts ...func(*probe.Sample)) probe.Sample {
	s := probe.Sample{
		Round: round, Mode: mode, Secure: true,
		Srv:   probe.Measured(ms(total / 4)),
		Total: probe.Measured(ms(total)),
	}
	if mode == probe.Cold {
		s.DNS = probe.Measured(ms(1))
		s.TCP = probe.Measured(ms(10))
		s.TLS = probe.Measured(ms(20))
	} else {
		s.Wait = probe.Measured(0)
		s.Reused = true
	}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func TestComputeExcludesWarmupAndNewConn(t *testing.T) {
	samples := []probe.Sample{
		sample(1, probe.Cold, 200, func(s *probe.Sample) { s.IsWarmup = true }),
		sample(1, probe.Warm, 150, func(s *probe.Sample) { s.IsWarmup = true; s.Reused = false }),
		sample(2, probe.Cold, 100),
		sample(2, probe.Warm, 40),
		sample(3, probe.Cold, 120),
		// ok, but it had to dial: counted as new conn, kept out of timings.
		sample(3, probe.Warm, 90, func(s *probe.Sample) { s.Reused = false }),
		sample(4, probe.Cold, 110),
		sample(4, probe.Warm, 50),
	}
	sum := Compute(samples, 4*time.Second, 1)

	if sum.Cold.N != 3 {
		t.Errorf("cold N = %d, want 3 (warmup round excluded)", sum.Cold.N)
	}
	if sum.Warm.N != 2 {
		t.Errorf("warm N = %d, want 2 (warmup and new-conn excluded)", sum.Warm.N)
	}
	if sum.NewConn != 1 {
		t.Errorf("NewConn = %d, want 1", sum.NewConn)
	}
	if sum.Cold.Sent != 3 || sum.Warm.Sent != 3 {
		t.Errorf("Sent = cold %d / warm %d, want 3 / 3", sum.Cold.Sent, sum.Warm.Sent)
	}
	if sum.Warm.OK != 3 {
		t.Errorf("warm OK = %d, want 3: a new connection is not a failure", sum.Warm.OK)
	}
	if sum.Warm.Loss != 0 {
		t.Errorf("warm loss = %v, want 0", sum.Warm.Loss)
	}
}

func TestComputeLossIsPerMode(t *testing.T) {
	samples := []probe.Sample{
		sample(1, probe.Cold, 100, func(s *probe.Sample) { s.Err = errors.New("timeout") }),
		sample(1, probe.Warm, 40),
		sample(2, probe.Cold, 100),
		sample(2, probe.Warm, 40),
	}
	sum := Compute(samples, time.Second, 0)
	if sum.Cold.Loss != 0.5 {
		t.Errorf("cold loss = %v, want 0.5", sum.Cold.Loss)
	}
	if sum.Warm.Loss != 0 {
		t.Errorf("warm loss = %v, want 0: failures are counted per mode", sum.Warm.Loss)
	}
	if sum.Cold.N != 1 {
		t.Errorf("cold N = %d, want 1: the failed sample must not enter timings", sum.Cold.N)
	}
}

func TestP95SuppressedBelowThreshold(t *testing.T) {
	var samples []probe.Sample
	for i := 1; i <= MinP95Samples-1; i++ {
		samples = append(samples, sample(i, probe.Cold, 100+i))
	}
	if sum := Compute(samples, time.Second, 0); sum.Cold.P95.OK {
		t.Errorf("p95 reported at n=%d, want suppressed below %d", sum.Cold.N, MinP95Samples)
	}

	samples = append(samples, sample(MinP95Samples, probe.Cold, 200))
	sum := Compute(samples, time.Second, 0)
	if !sum.Cold.P95.OK {
		t.Fatalf("p95 suppressed at n=%d, want reported", sum.Cold.N)
	}
	// Values are 101..119 plus one 200. At n=20 nearest-rank picks rank
	// ceil(0.95*20) = 19, so the outlier at rank 20 is not the answer.
	if sum.Cold.P95.D != ms(119) {
		t.Errorf("p95 = %v, want 119ms (rank 19 of 20)", sum.Cold.P95.D)
	}
}

func TestOverheadIsSummedWithinSample(t *testing.T) {
	samples := []probe.Sample{
		sample(1, probe.Cold, 100),
		sample(2, probe.Cold, 120),
		// tls never completed: this sample cannot contribute to overhead.
		sample(3, probe.Cold, 130, func(s *probe.Sample) { s.TLS = probe.Phase{} }),
	}
	sum := Compute(samples, time.Second, 0)
	if want := ms(31); sum.Overhead != want {
		t.Errorf("Overhead = %v, want %v (dns 1 + tcp 10 + tls 20)", sum.Overhead, want)
	}
	if sum.OverheadSkipped != 1 {
		t.Errorf("OverheadSkipped = %d, want 1", sum.OverheadSkipped)
	}
	if sum.OverheadDNS != ms(1) || sum.OverheadTCP != ms(10) || sum.OverheadTLS != ms(20) {
		t.Errorf("overhead split = %v/%v/%v, want 1/10/20ms", sum.OverheadDNS, sum.OverheadTCP, sum.OverheadTLS)
	}
	if sum.Overhead < 0 {
		t.Error("handshake overhead is a sum of durations and can never be negative")
	}
}

// TestOverheadWorksWithoutTLS covers a plain http target: there is no handshake
// to measure, so requiring a TLS phase would exclude every single sample and
// report an overhead of zero.
func TestOverheadWorksWithoutTLS(t *testing.T) {
	var samples []probe.Sample
	for i := 1; i <= 3; i++ {
		s := sample(i, probe.Cold, 100)
		s.Secure = false
		s.TLS = probe.Phase{} // http:// never handshakes
		samples = append(samples, s)
	}
	sum := Compute(samples, time.Second, 0)

	if sum.OverheadSkipped != 0 {
		t.Errorf("OverheadSkipped = %d, want 0: an http target has no TLS phase to miss", sum.OverheadSkipped)
	}
	if want := ms(11); sum.Overhead != want {
		t.Errorf("Overhead = %v, want %v (dns 1 + tcp 10)", sum.Overhead, want)
	}
	if sum.OverheadTLS != 0 {
		t.Errorf("OverheadTLS = %v, want 0", sum.OverheadTLS)
	}
}

// TestOverheadSkipsIncompleteHTTPS is the mirror: over https a missing TLS
// phase does mean the sample is incomplete.
func TestOverheadSkipsIncompleteHTTPS(t *testing.T) {
	s := sample(1, probe.Cold, 100)
	s.TLS = probe.Phase{}
	sum := Compute([]probe.Sample{s}, time.Second, 0)
	if sum.OverheadSkipped != 1 {
		t.Errorf("OverheadSkipped = %d, want 1", sum.OverheadSkipped)
	}
}

func TestGainAndPairedGain(t *testing.T) {
	samples := []probe.Sample{
		sample(1, probe.Cold, 100), sample(1, probe.Warm, 40),
		sample(2, probe.Cold, 120), sample(2, probe.Warm, 30),
		sample(3, probe.Cold, 110), sample(3, probe.Warm, 50),
	}
	sum := Compute(samples, time.Second, 0)
	if want := ms(110) - ms(40); sum.Gain != want {
		t.Errorf("Gain = %v, want %v", sum.Gain, want)
	}
	// Paired differences: 60, 90, 60 -> median 60.
	if !sum.PairedGain.OK || sum.PairedGain.D != ms(60) {
		t.Errorf("PairedGain = %v (OK=%v), want 60ms", sum.PairedGain.D, sum.PairedGain.OK)
	}
}

func TestPairedGainNeedsBothSides(t *testing.T) {
	samples := []probe.Sample{
		sample(1, probe.Cold, 100),
		sample(2, probe.Warm, 40),
	}
	if sum := Compute(samples, time.Second, 0); sum.PairedGain.OK {
		t.Error("PairedGain reported although no round had both a cold and a warm sample")
	}
}

func TestGainMayBeNegative(t *testing.T) {
	samples := []probe.Sample{
		sample(1, probe.Cold, 30), sample(1, probe.Warm, 80),
	}
	if sum := Compute(samples, time.Second, 0); sum.Gain >= 0 {
		t.Errorf("Gain = %v, want negative: a slower warm side must be visible", sum.Gain)
	}
}
