// Command tlsping measures what an HTTPS connection costs, phase by phase, and
// compares a new connection against a reused one in the same time window.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/drvoss/tlsping/internal/cli"
	"github.com/drvoss/tlsping/internal/probe"
	"github.com/drvoss/tlsping/internal/render"
	"github.com/drvoss/tlsping/internal/stats"
)

// Version follows semver, starting at 0.1.0 (PLAN §3).
const Version = "0.1.0"

// Exit codes (PLAN §3).
const (
	exitOK      = 0
	exitPartial = 1
	exitAllFail = 2
	exitUsage   = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr *os.File) int {
	cfg, err := cli.Parse(args, Version, stdout)
	if err != nil {
		if errors.Is(err, cli.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "tlsping:", err)
		fmt.Fprintln(stderr, "run 'tlsping --help' for usage")
		return exitUsage
	}

	r := newRenderer(cfg, stdout, stderr)
	for _, w := range cfg.Warnings {
		r.Warn(w)
	}

	// Ctrl+C cancels the run; the samples already taken are still summarised.
	// Handling is released as soon as the first signal lands, so a second Ctrl+C
	// kills the process outright rather than being swallowed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()

	runner := probe.NewRunner(cfg.Probe(), r.Warn)
	info, err := runner.Preflight(ctx)
	if err != nil {
		// Nothing was measured, so there is no partial result to report.
		fmt.Fprintln(stderr, "tlsping: preflight failed:", err)
		return exitAllFail
	}
	info.Version = Version
	r.Header(info)

	samples, elapsed, runErr := collect(ctx, runner, r)
	if runErr != nil {
		fmt.Fprintln(stderr, "tlsping:", runErr)
	}
	r.Summary(stats.Compute(samples, elapsed, cfg.Warmup))

	// A result the user never received is not a success, however well the
	// measurements themselves went.
	if f, ok := r.(render.Failer); ok {
		if err := f.Err(); err != nil {
			fmt.Fprintln(stderr, "tlsping: writing output:", err)
			return exitAllFail
		}
	}
	return exitCode(samples)
}

// collect drains every sample the runner produces. The channel must be drained
// until close, which is the contract Runner.Run documents.
func collect(ctx context.Context, runner *probe.Runner, r render.Renderer) ([]probe.Sample, time.Duration, error) {
	ch := make(chan probe.Sample, 8)
	start := time.Now()

	var runErr error
	go func() {
		defer close(ch)
		runErr = runner.Run(ctx, ch)
	}()

	var samples []probe.Sample
	for s := range ch {
		samples = append(samples, s)
		r.Sample(s)
	}
	// The range ended because the channel closed, which happens-after the
	// assignment above, so reading runErr here is safe.
	return samples, time.Since(start), runErr
}

func newRenderer(cfg *cli.Config, stdout, stderr *os.File) render.Renderer {
	switch {
	case cfg.JSON:
		return render.NewJSON(stdout, stderr, Version)
	case cfg.CSV:
		return render.NewCSV(stdout, stderr)
	}
	width := render.TerminalWidth(stdout)
	return render.NewTable(stdout, stderr, render.Options{
		Verbose:  cfg.Verbose,
		Quiet:    cfg.Quiet,
		Color:    render.ColorEnabled(cfg.NoColor, stdout),
		ErrColor: render.ColorEnabled(cfg.NoColor, stderr),
		Width:    width,
		Layout:   render.PickLayout(width),
	})
}

// exitCode reports success over the samples that count. Warmup rounds are
// excluded, unless they are all there is.
func exitCode(samples []probe.Sample) int {
	counted := make([]probe.Sample, 0, len(samples))
	for _, s := range samples {
		if !s.IsWarmup {
			counted = append(counted, s)
		}
	}
	if len(counted) == 0 {
		counted = samples
	}
	if len(counted) == 0 {
		return exitAllFail
	}

	ok := 0
	for _, s := range counted {
		if s.Responded() {
			ok++
		}
	}
	switch {
	case ok == len(counted):
		return exitOK
	case ok == 0:
		return exitAllFail
	default:
		return exitPartial
	}
}
