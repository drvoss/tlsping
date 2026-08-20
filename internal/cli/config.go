// Package cli parses and validates flags. It depends on probe for the shared
// enums and nothing else (PLAN §5.1).
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/drvoss/tlsping/internal/probe"
)

// ErrHelp is returned when --help or --version was handled and the process
// should exit successfully without measuring.
var ErrHelp = errors.New("help requested")

// MinInterval is the hard floor between rounds. It applies in unlimited mode
// too, so the tool can never turn into a load generator (PLAN §4.5).
const MinInterval = 200 * time.Millisecond

// Config is the parsed command line.
type Config struct {
	URL *url.URL

	Count    int
	Interval time.Duration
	Timeout  time.Duration
	Warmup   int
	Mode     probe.RunMode
	Order    string
	Method   string // "" means detect in the preflight

	HTTPVersion string
	CacheBust   bool
	PinIP       bool
	IPVersion   int
	Insecure    bool
	Headers     http.Header

	JSON, CSV bool
	NoColor   bool
	Quiet     bool
	Verbose   bool

	Version string
	// Warnings collected while parsing, e.g. a clamped interval. They are
	// emitted once a renderer exists.
	Warnings []string
}

type headerFlag struct{ values []string }

func (h *headerFlag) String() string { return strings.Join(h.values, ",") }
func (h *headerFlag) Set(v string) error {
	if !strings.Contains(v, ":") {
		return fmt.Errorf("header %q must be in Name: value form", v)
	}
	h.values = append(h.values, v)
	return nil
}

// Parse reads args and produces a validated Config.
func Parse(args []string, version string, out io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("tlsping", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		count       int
		interval    time.Duration
		timeout     time.Duration
		warmup      int
		mode        string
		order       string
		method      string
		httpVersion string
		cacheBust   bool
		noPinIP     bool
		v4, v6      bool
		insecure    bool
		headers     headerFlag
		asJSON      bool
		asCSV       bool
		noColor     bool
		quiet       bool
		verbose     bool
		showVersion bool
		help        bool
	)

	// Short and long spellings bind to the same variable, which is how the
	// flag package supports aliases.
	intVar := func(p *int, def int, names ...string) {
		for _, n := range names {
			fs.IntVar(p, n, def, "")
		}
	}
	durVar := func(p *time.Duration, def time.Duration, names ...string) {
		for _, n := range names {
			fs.DurationVar(p, n, def, "")
		}
	}
	strVar := func(p *string, def string, names ...string) {
		for _, n := range names {
			fs.StringVar(p, n, def, "")
		}
	}
	boolVar := func(p *bool, names ...string) {
		for _, n := range names {
			fs.BoolVar(p, n, false, "")
		}
	}

	intVar(&count, 10, "n", "c", "count")
	intVar(&warmup, 1, "warmup")
	durVar(&interval, time.Second, "i", "interval")
	durVar(&timeout, 5*time.Second, "w", "timeout")
	strVar(&mode, "both", "m", "mode")
	strVar(&order, "alternate", "order")
	strVar(&method, "", "X", "method")
	strVar(&httpVersion, "auto", "http-version")
	boolVar(&cacheBust, "cache-bust")
	boolVar(&noPinIP, "no-pin-ip")
	boolVar(&v4, "4")
	boolVar(&v6, "6")
	boolVar(&insecure, "k", "insecure")
	boolVar(&asJSON, "json")
	boolVar(&asCSV, "csv")
	boolVar(&noColor, "no-color")
	boolVar(&quiet, "q", "quiet")
	boolVar(&verbose, "v")
	boolVar(&showVersion, "version")
	boolVar(&help, "h", "help")
	fs.Var(&headers, "H", "")
	fs.Var(&headers, "header", "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			Usage(out, version)
			return nil, ErrHelp
		}
		return nil, err
	}
	if help {
		Usage(out, version)
		return nil, ErrHelp
	}
	if showVersion {
		fmt.Fprintf(out, "tlsping %s\n", version)
		return nil, ErrHelp
	}

	cfg := &Config{
		Count:       count,
		Interval:    interval,
		Timeout:     timeout,
		Warmup:      warmup,
		Order:       order,
		Method:      strings.ToUpper(method),
		HTTPVersion: httpVersion,
		CacheBust:   cacheBust,
		PinIP:       !noPinIP,
		Insecure:    insecure,
		Headers:     http.Header{},
		JSON:        asJSON,
		CSV:         asCSV,
		NoColor:     noColor,
		Quiet:       quiet,
		Verbose:     verbose,
		Version:     version,
	}

	if fs.NArg() < 1 {
		return nil, errors.New("missing target: tlsping [flags] <host|url>")
	}
	if fs.NArg() > 1 {
		// Multiple hosts are explicitly out of scope for v1 (PLAN §4.6).
		return nil, fmt.Errorf("only one target is supported, got %d", fs.NArg())
	}
	u, err := probe.NormalizeTarget(fs.Arg(0))
	if err != nil {
		return nil, err
	}
	cfg.URL = u

	if err := cfg.applyMode(mode); err != nil {
		return nil, err
	}
	if err := cfg.applyIPVersion(v4, v6); err != nil {
		return nil, err
	}
	if err := cfg.applyHTTPVersion(); err != nil {
		return nil, err
	}
	if err := cfg.applyHeaders(headers.values); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyMode(mode string) error {
	switch strings.ToLower(mode) {
	case "both":
		c.Mode = probe.Both
	case "cold":
		c.Mode = probe.ColdOnly
	case "warm":
		c.Mode = probe.WarmOnly
	default:
		return fmt.Errorf("invalid -m %q: want both, cold or warm", mode)
	}
	return nil
}

func (c *Config) applyIPVersion(v4, v6 bool) error {
	switch {
	case v4 && v6:
		return errors.New("-4 and -6 are mutually exclusive")
	case v4:
		c.IPVersion = 4
	case v6:
		c.IPVersion = 6
	}
	return nil
}

func (c *Config) applyHTTPVersion() error {
	switch c.HTTPVersion {
	case "auto", "1.1", "2":
		return nil
	case "3":
		// Explicitly named so the message can say why, rather than "invalid
		// value" (PLAN §4.6).
		return errors.New("--http-version 3 is not supported in v1: HTTP/3 needs a QUIC stack and is planned for a later release")
	default:
		return fmt.Errorf("invalid --http-version %q: want auto, 1.1 or 2", c.HTTPVersion)
	}
}

func (c *Config) applyHeaders(values []string) error {
	for _, h := range values {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("header %q must be in Name: value form", h)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("header %q has an empty name", h)
		}
		c.Headers.Add(name, strings.TrimSpace(value))
	}
	return nil
}

func (c *Config) validate() error {
	if c.JSON && c.CSV {
		return errors.New("--json and --csv are mutually exclusive")
	}
	if c.Quiet && c.Verbose {
		return errors.New("-q and -v are mutually exclusive")
	}
	if c.Count < 0 {
		return fmt.Errorf("invalid count %d: want 0 for unlimited or a positive number", c.Count)
	}
	if c.Warmup < 0 {
		return fmt.Errorf("invalid --warmup %d: want 0 or more", c.Warmup)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("invalid --timeout %s: want a positive duration", c.Timeout)
	}
	switch c.Order {
	case "alternate", "cold-first", "warm-first":
	default:
		return fmt.Errorf("invalid --order %q: want alternate, cold-first or warm-first", c.Order)
	}
	if c.Method != "" {
		for _, r := range c.Method {
			if r < 'A' || r > 'Z' {
				return fmt.Errorf("invalid -X %q", c.Method)
			}
		}
	}

	if c.Interval < MinInterval {
		c.Warnings = append(c.Warnings,
			fmt.Sprintf("interval raised from %s to the %s floor", c.Interval, MinInterval))
		c.Interval = MinInterval
	}
	if c.Count > 0 && c.Warmup >= c.Count {
		c.Warnings = append(c.Warnings,
			fmt.Sprintf("--warmup %d excludes every one of the %d rounds, so the statistics will be empty", c.Warmup, c.Count))
	}
	return nil
}

// Probe converts the CLI config into the runner's config.
func (c *Config) Probe() probe.Config {
	return probe.Config{
		URL:         c.URL,
		Method:      c.Method,
		Headers:     c.Headers,
		UA:          "tlsping/" + c.Version,
		Count:       c.Count,
		Interval:    c.Interval,
		Timeout:     c.Timeout,
		Warmup:      c.Warmup,
		Mode:        c.Mode,
		Order:       c.Order,
		HTTPVersion: c.HTTPVersion,
		CacheBust:   c.CacheBust,
		PinIP:       c.PinIP,
		IPVersion:   c.IPVersion,
		Insecure:    c.Insecure,
		MaxBody:     probe.DefaultMaxBody,
		MaxFails:    3,
	}
}

// Usage prints the help text.
func Usage(w io.Writer, version string) {
	fmt.Fprintf(w, `tlsping %s — HTTPS connection cost diagnostic

Measures one HTTPS request broken into phases, and compares a brand new
connection (cold) against a reused one (warm) inside the same time window.

usage:
  tlsping [flags] <host|url>

flags:
  -n, -c, --count N       measurements to take, 0 for unlimited (default 10)
  -i, --interval D        gap between rounds, floor %s (default 1s)
  -w, --timeout D         per-request timeout, DNS through body (default 5s)
  -m, --mode M            both | cold | warm (default both)
      --order O           alternate | cold-first | warm-first
                          (default alternate: the order flips every round)
      --warmup N          leading rounds excluded from statistics (default 1)
  -X, --method M          HTTP method; by default HEAD, falling back to
                          GET + Range on a 405/501 during the preflight
      --http-version V    auto | 1.1 | 2                          (default auto)
      --cache-bust        append ?_=<seq> to each request
      --no-pin-ip         resolve per round instead of pinning one address
  -4, -6                  force the IP version
  -k, --insecure          skip certificate verification
  -H, --header 'N: v'     extra request header, repeatable
      --json, --csv       machine-readable output, mutually exclusive
      --no-color          never emit ANSI colour
  -q, --quiet             collapse the table to totals and status codes; the
                          statistics block is still printed
  -v                      per-round residual and TLS resumption, plus paired
                          gain, new-conn counter, certificate chain length and
                          the handshake samples excluded for a missing phase
                          (-q and -v cannot be combined)
      --version           print the version

exit codes:
  0 every measurement succeeded
  1 some measurements failed
  2 every measurement failed, or the preflight or the output failed
  3 usage error

A run stopped early by 429, 503 + Retry-After or repeated failures still exits
0 when the samples it did collect succeeded; the reason goes to stderr.

Only measure hosts you own or have permission to test.
`, version, MinInterval)
}
