# tlsping

**한국어 문서: [README.ko.md](README.ko.md)**

**An HTTPS connection cost diagnostic.** It makes the TLS handshake visible, and measures a brand-new connection against a reused one inside the same time window.

```
     |  COLD  new connection         |  WARM  keep-alive |
     |   dns   tcp   tls   srv total |  wait   srv total | code
-----+-------------------------------+-------------------+-------
   2 |     0   118   129   234   482 |     0   129   129 | 200
```

That row says the whole story: connecting to this endpoint costs 482 ms, **129 ms of which is the TLS handshake**, and once the connection exists the same request takes 129 ms.

> ⚠️ **Only measure hosts you own or have permission to test.** Repeated requests can get your IP flagged by a WAF or IPS. The defaults (10 rounds, 1 s apart) are chosen to be safe — think before you raise them.

- Single static binary, **no dependencies** — Go standard library only
- Windows / Linux / macOS × amd64 / arm64
- MIT licensed

---

## Why this exists

If a page feels slow to connect to, you want to know *which part* is slow. `ping` cannot tell you: many servers drop ICMP entirely, and even when they answer, ICMP says nothing about DNS, TLS or how long the server took to think.

The obvious answer is `httping`, which is excellent and has 17 years of features behind it. But two things it structurally cannot do are the two things you most want when the endpoint is HTTPS:

**1. It never shows you the TLS handshake.** `httping` does measure `ssl_handshake` — then subtracts it from the connect time and prints it nowhere, in any output mode. On an HTTPS target the single most expensive step is absent from the breakdown, and the five stages it does print no longer add up to the total.

**2. It cannot compare a new connection against a reused one fairly.** You can run it twice, once with `-Q` for keep-alive. But those two runs sit in different time windows: network congestion, routing, server load and CDN edge assignment all move in between. Any difference you see is confounded — you cannot tell "connection reuse helped" apart from "the network changed."

`tlsping` interleaves both modes round by round and **alternates their order every round**, so both share the same time window and the confounders cancel out. That is a *paired* comparison, and it is statistically stronger than running a tool twice.

So the question this tool answers is narrow and specific:

> **What does it cost to reach this HTTPS endpoint for the first time, how much of that is TLS, and how much faster is it when the connection is already open?**

---

## Install

Requires Go 1.26.6 or newer. This patch minimum includes standard-library
security fixes used by URL, TLS, and certificate code paths.

Install directly:

```sh
go install github.com/drvoss/tlsping@latest
```

Or build from a local clone:

```sh
# From a local clone of this repository:
go build -o tlsping .
```

The result is a self-contained binary — drop it anywhere on your `PATH`. Cross-compiling needs nothing but the Go toolchain:

```sh
GOOS=linux   GOARCH=arm64 go build -o dist/tlsping-linux-arm64      .
GOOS=darwin  GOARCH=arm64 go build -o dist/tlsping-darwin-arm64     .
GOOS=windows GOARCH=amd64 go build -o dist/tlsping-windows-amd64.exe .
```

> **No pre-built binaries yet.** Building from source is currently the only install path. See [Project status](#project-status).

---

## Quick start

```
tlsping [flags] <host|url>
```

```
$ tlsping -n 8 -i 400ms example.com

HEAD https://example.com/ -> 172.66.147.243:443   h2 · TLS1.3 · 0 bytes
8 rounds, 400ms interval, order=alternate; all times in ms, "-" = not measured

     |  COLD  new connection         |  WARM  keep-alive |
     |   dns   tcp   tls   srv total |  wait   srv total | code
-----+-------------------------------+-------------------+-------
   1 |     0   116   241   233   593 |   357   241   599 | 200      warmup·new conn
   2 |     0   118   129   234   482 |     0   129   129 | 200
   3 |     0   117   128   235   481 |     0   126   126 | 200
   4 |     2   119   508   237   868 |     0   121   121 | 200
   5 |     0   117   123   234   476 |     0   125   126 | 200
   6 |     2   117   122   234   476 |     0   124   125 | 200
   7 |     0   118   123   236   478 |     0   124   125 | 200
   8 |     0   121   122   233   477 |     0   123   124 | 200

--- example.com  statistics ---
  n = 7 (warmup 1 excluded), elapsed 6.6s
                        cold        warm
  ok / sent              7/7         7/7
  loss                  0.0%        0.0%
  min                  476ms       121ms
  mean                 534ms       125ms
  median               478ms       125ms
  max                  868ms       129ms
  mdev                 136ms         2ms
  p95                      -           -
  (p95 needs n >= 20)

  handshake overhead  =  +243ms   median(dns+tcp+tls) per cold sample
    dns 0ms · tcp 118ms · tls 123ms  (per-stage medians)
  keep-alive gain     =  +353ms   median(cold.total) - median(warm.total)  [reference]
```

**How to read this.**

- Round 1's `tls 241` drops to `~123` from round 2 on. That is **TLS session resumption** — the second handshake reuses a session ticket and skips a round trip. This is exactly the number `httping` hides.
- Reaching this endpoint cold costs ~478 ms, and 243 ms of that is pure handshake overhead (`dns + tcp + tls`). Reusing the connection brings it to 125 ms.
- Round 4 spiked to `tls 508`. One bad handshake dragged `mean` (534) far above `median` (478) and pushed `mdev` to 136 ms. That gap between mean and median *is* the signal — a stable endpoint has them close together.
- The `warmup` round is excluded from every statistic. The first warm request always has to dial, because the shared connection does not exist yet — that is what `new conn` and the large `wait 357` mean.

---

## What it measures

| Stage | Key | Interval | What it tells you |
|---|---|---|---|
| DNS | `dns` | measured directly via `LookupNetIP` | resolver latency (independent of network RTT) |
| Pool wait | `wait` | `GetConn` → `GotConn` | time spent waiting for a connection from the pool |
| TCP | `tcp` | `ConnectStart` → `ConnectDone` | **approximate** RTT (see [Limitations](#limitations)) |
| TLS | `tls` | `TLSHandshakeStart` → `Done` | 1–2 RTTs plus cryptographic work |
| Server | `srv` | `WroteRequest` → `GotFirstResponseByte` | 1 RTT plus the server's own processing time |
| Total | `total` | mode-specific start → body EOF | independently measured wall time |

### The two modes decompose differently

`wait` spans `GetConn` → `GotConn`, and on a **new** connection that interval swallows the dial and the whole TLS handshake. Adding `dns + wait + tcp + tls + srv` would double-count. So each mode gets its own non-overlapping decomposition:

```
cold (new connection)      clock starts at the DNS lookup
                           total = dns + tcp + tls + srv + other
                           wait is not recorded ("-")

warm (connection reused)   clock starts immediately before Client.Do
                           total = wait + srv + other
                           dns/tcp/tls never happen ("-")
```

`total` is measured independently rather than summed, so `total ≥ sum of stages` always holds. The remainder is `other` — request header transmission, body reception, runtime overhead — shown under `-v`. If `other` exceeds 20 % of `total`, you get a warning.

**A `-` in the table means "not measured", never 0 ms.** Reaching only some stages before an error is normal and is reported honestly.

### Why warm is needed at all

The cold breakdown alone already gives you the handshake cost. Warm answers three things it cannot:

1. **Does the server actually honour keep-alive?** A server that closes the connection shows up in the `new conn` counter.
2. **Does server processing time (`srv`) change on an established connection?** HTTP/2 multiplexing and server-side session state can move it.
3. **Is there connection-pool contention (`wait`) on reuse?**

> **TLS session resumption shows up in cold, not warm.** A warm request reuses keep-alive, so no handshake happens at all and `tls` is unmeasured. Ticket reuse appears instead as cold's `tls` dropping from the second round on.

### Statistics

- **`mdev` is the population standard deviation**, matching what iputils `ping` prints under that name — despite the name, it is not a mean absolute deviation.
- **`p95` is only computed at n ≥ 20.** At n = 4 the 95th percentile is just the maximum, which carries no information. Percentiles use nearest-rank with no interpolation.
- **`handshake overhead` is the median of `dns + tcp + tls` summed *within* each cold sample.** Because it sums values from a single request it is statistically sound, and being a sum of durations it can never be negative. Note that the per-stage medians printed beneath it need not add up to it — the median of a sum is not the sum of the medians.
- **`keep-alive gain` is `median(cold.total) − median(warm.total)`, and it is labelled `[reference]` on purpose.** Subtracting percentiles of two different distributions is not a real statistic. Under `-v` you also get the median of the per-round paired difference, which *is* defensible.

### Success and failure

| Class | Condition | Handling |
|---|---|---|
| Success | an HTTP response arrived (any status: 2xx/3xx/4xx/5xx) | included in the timing statistics |
| Failure | no response — DNS failure, connection refused, TLS error, timeout, body read error | counted as loss, excluded from timings |

4xx and 5xx are not failures because this tool measures **latency**, not availability. A 404 still gives you a valid round trip time.

A warm sample with `Reused == false` is **not a failure** either. It counts as ok, is kept out of the timings, and is reported through the `new conn` counter — a high count means the server is not holding connections open, which is itself useful information.

**The first warm request is always `Reused == false`**, since the shared transport has no connection yet and that request must dial and handshake itself. That is why `--warmup` defaults to 1.

---

## Output

### Symbols

`-` means different things in different places. Do not conflate them.

| Where | Meaning of `-` |
|---|---|
| a stage cell (`dns`/`tcp`/`tls`/`wait`) | **not measured** — not 0 ms. Either that mode never pays for the stage, or an error stopped short of it |
| `-/200` in the `code` column | left is **cold**, right is **warm**. `-` means that side got no response |
| the `p95` row | fewer than 20 usable samples, so it is not computed |
| `min`/`mean`/… rows | no sample was eligible for the timing statistics |

A round annotated `warmup` is excluded from every statistic — that is what `n = 7 (warmup 1 excluded)` reports.

### When something fails

Only the failing mode's cells are replaced with a reason; the other side still prints normally. Loss is tallied per mode.

```
   5 |     0    34    71    41   148 |     1    40    42 | 200
   6 |         timeout (5s)          |     0    33    34 | -/200
```

Round 6's cold probe timed out while warm answered in 34 ms, and `-/200` says exactly that.

Reason strings: `timeout (5s)`, `conn refused`, `conn reset`, `dns fail`, `unreachable`, `TLS: cert expired`, `TLS: cert name`, `TLS: unknown CA`, `TLS: cert invalid`, `TLS error`, `conn closed`, `body error`, `canceled`.

### Narrow terminals

The layout is chosen from the terminal width automatically; `COLUMNS` overrides it.

**70–99 columns** — two stacked lines per round:

```
  #2   COLD dns    0 tcp   31 tls   63 srv   32 =   128ms 200
       WARM wait   0                   srv   32 =    33ms 200
```

**Under 70 columns** — the whole cold block, then the whole warm block:

```
COLD
   2 dns    0 tcp   31 tls   63 srv   32 = 128ms 200
   3 dns    0 tcp   33 tls   67 srv   38 = 140ms 200

WARM
   2 wait   0 srv   32 = 33ms 200
   3 wait   0 srv   37 = 38ms 200
```

The narrowest layout loses the side-by-side round pairing. If you need the paired view, widen the terminal or use `--json`.

### `-q` and `-v`

`-q` collapses **the table only** to totals and status codes; the statistics block still prints in full. Failure reasons move from the cell to a trailing note, since six columns cannot hold them without truncation.

```
     |  COLD |  WARM |
     | total | total | code
-----+-------+-------+-------
   6 |   err |    34 | -/200    cold timeout (5s)
```

`-v` adds the `other` residual and TLS resumption per round, and appends the paired gain, the `new conn` counter, the certificate chain length, ALPN and the number of samples excluded from the overhead aggregate. `-q` and `-v` cannot be combined.

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-n, -c, --count N` | `10` | number of measurements; `0` runs until Ctrl+C |
| `-i, --interval D` | `1s` | gap between rounds, floor of `200ms` enforced |
| `-w, --timeout D` | `5s` | per-request timeout, covering DNS through body EOF |
| `-m, --mode M` | `both` | `both` \| `cold` \| `warm` |
| `--order O` | `alternate` | or pin the order with `cold-first` \| `warm-first` |
| `--warmup N` | `1` | leading **rounds** excluded from the statistics |
| `-X, --method M` | auto | unset means HEAD, falling back to `GET` + `Range: bytes=0-0` on a 405/501 |
| `--http-version V` | `auto` | `1.1` \| `2`. **`3` is unsupported** and exits with code 3 |
| `--cache-bust` | off | append `?_=<seq>` to each request |
| `--no-pin-ip` | — | resolve per round instead of pinning one address (pinning is the default) |
| `-4` / `-6` | auto | force the IP version |
| `-k, --insecure` | off | skip certificate verification |
| `-H, --header 'N: v'` | — | extra request header, repeatable |
| `--json` / `--csv` | — | machine-readable output, mutually exclusive |
| `--no-color` | — | never emit ANSI colour (`NO_COLOR` is honoured too) |
| `-q, --quiet` | — | collapse the table to totals and status codes |
| `-v` | — | residual, TLS detail, paired gain, new-conn counter |
| `--version` | — | print the version |

**Input normalisation**: `google.com` becomes `https://google.com/`. A missing scheme defaults to https.

### Exit codes

| Code | Condition |
|---|---|
| `0` | every measured sample got a response |
| `1` | some samples got no response |
| `2` | every sample failed, the preflight failed, or the output could not be written |
| `3` | usage error |

Judgement uses **non-warmup** samples (or the warmup samples alone, if that is all there is). Status codes are not part of it — a 404 still produced a valid round trip.

**An early stop is not reflected in the exit code.** If `429`, `503 + Retry-After` or the consecutive-failure guard cuts the run short, the code is still `0` when every collected sample succeeded. In automation, detect it from the stderr warning, or from `warnings[]` and the `samples` count in `--json`.

---

## Machine-readable output

### `--json`

One document on stdout when the run ends. The `schema` field is the format version and increments on any incompatible change.

```sh
tlsping -n 20 --json example.com | jq '.summary.cold.median_ms'
tlsping -n 20 --json example.com | jq -r '.samples[] | select(.mode=="cold") | .tls_ms'
tlsping --json example.com | jq '.summary.handshake_overhead_ms'
```

| Field | Meaning |
|---|---|
| `schema` | format version (currently `1`) |
| `run` | target, resolved method/address/protocol/TLS version, and the settings used |
| `samples[]` | per-sample stages. **Unmeasured stages are `null`**, which is distinct from `0` |
| `samples[].error_kind` | stable failure code — `timeout`, `conn_refused`, `dns_fail`, `cert_expired`, `cert_name`, `cert_unknown_ca`, `cert_invalid`, `tls_error`, `conn_closed`, `conn_reset`, `unreachable`, `body_error`, `canceled`, `error` |
| `samples[].error` | raw error text — for display, not stable across versions |
| `samples[].cert_chain_len` | present only on samples where a handshake actually happened |
| `summary` | cold/warm aggregates, overhead breakdown, gain, paired gain, resumption count |
| `warnings[]` | warnings that also went to stderr |

All time fields are milliseconds with sub-millisecond precision. `p95_ms` is `null` below n = 20.

Parse `error_kind`, not `error`. The former is part of the schema; the latter is free text.

### `--csv`

One **streamed** row per sample. The summary is not included — use `--json` if you need it. Unmeasured stages are empty fields.

```
round,mode,warmup,dns_ms,tcp_ms,tls_ms,wait_ms,srv_ms,total_ms,other_ms,reused,
new_conn,retries,status,proto,tls_version,alpn,tls_resumed,cert_chain_len,bytes,
addr,body_overflow,error_kind,error
```

---

## How it works

**Preflight.** One request before measuring begins, to settle two things: the method (falling back from HEAD to a ranged GET on 405/501), and the facts that only an established connection can reveal — the peer address, the negotiated protocol and the TLS version. Doing the HEAD→GET fallback mid-run would make one round cost two connections and break the connection-count invariant, so it happens outside the rounds. The preflight is excluded from every statistic; if it fails, nothing is measured and the process exits with code 2.

**IP pinning (on by default).** The address settled during the preflight is used as the dial target for the whole run. Behind round-robin DNS or anycast, cold and warm would otherwise measure different servers and the comparison would be meaningless. **The URL hostname is left untouched**, so SNI and certificate verification still work correctly. Pinning disables proxying, and a detected proxy environment produces a warning.

**DNS.** With pinning on, `DialContext` already receives an IP, so httptrace's DNS hooks never fire. DNS is therefore measured directly with `LookupNetIP`, as the first step of the cold probe. That lookup exists to be timed; it does not change the dial target unless `--no-pin-ip` is set.

**Cold isolation.** A fresh `http.Transport` per round, `DisableKeepAlives`, and `CloseIdleConnections()` afterwards. This isolates **the connection pool only** — see [Limitations](#limitations).

**Redirects are never followed.** Following them would replay every trace hook per hop and blend several connections into a single sample. 3xx responses count as valid, and if the first response is a redirect the `Location` target is printed to stderr so you can re-run against the final URL.

**Safety valves.** Immediate stop on `429` or `503 + Retry-After`; stop after 3 consecutive failures; a hard 200 ms interval floor; and an identifiable `tlsping/<version>` User-Agent so server operators can see who you are.

---

## Limitations

Stated explicitly so you do not over-read the numbers.

| Item | Detail |
|---|---|
| **`tcp` is not ICMP RTT** | Server listen-backlog delay and firewall SYN filtering are mixed in. Treat it as an approximation. |
| **No TTL** | Go's `net/http` does not expose IP headers, so there is no equivalent of `ping`'s `TTL=`. The status code and negotiated protocol take its place. |
| **OS DNS cache** | `dns` drops to roughly zero from the second round on. In practice only the first sample is meaningful. |
| **Cold isolates the pool, nothing else** | The OS DNS cache, TLS session tickets and any server-side state are not isolated. In particular **cold transports share a TLS session cache**, so `tls` from round 2 onward reflects a *resumed* handshake. This is deliberate — it is how resumption becomes observable — and `-v` reports `tls resumed` so you can tell. For a full first-contact handshake every time, run the process repeatedly. |
| **`Reused` under HTTP/2** | On h2, `Reused == true` means "a new stream on an existing connection", not an exclusive connection. |
| **Cache busting can be ignored** | A CDN may serve a cached response despite `?_=`, and a WAF may read the pattern as scanning. Off by default. |
| **`--no-pin-ip` with a proxy** | `tcp` becomes the time to the proxy, and `dns` measures something not on the actual path. |
| **`--no-pin-ip` with `-m both`** | Cold follows each round's lookup while warm keeps the connection it first got, so under round-robin DNS the two modes can measure different servers. A warning is printed. |
| **64 KiB body cap** | Beyond it the connection cannot be drained and therefore cannot be reused (HTTP/1.x requires a full drain), so warm dials every time. A warning is printed. |
| **Colour threshold** | Output is appended live, so the "1.5× median" highlight uses the median **of the samples seen so far**. |

---

## Non-goals

Deliberately out of scope. Chasing feature breadth would dissolve what this tool is for.

- **Not a load tester** — concurrency of 1, 10 rounds by default
- **Not a monitoring daemon** — a one-shot CLI. Instead of a Nagios mode, use `--json` plus the exit code
- **Not a bandwidth meter** — HEAD by default
- Proxy/SOCKS5, TCP Fast Open, TOS/priority, MTU control, cookies, web authentication and FFT graphs are explicit non-goals
- HTTP/3, redirect following (`--follow`), multi-host comparison and a TUI are deferred to a later release

If you need any of these, [`httping`](https://www.vanheusden.com/httping/) very likely already has them.

---

## Project status

**v0.1.0 — early.** The measurement core is tested and the invariants are enforced by regression tests, but nothing here has been through wide real-world use yet.

- The **CLI flags and the `--json`/`--csv` schema may still change** before v1.0. `schema` is versioned so consumers can pin.
- No pre-built binaries, and no package-manager distribution yet.
- Verified on Windows, and cross-compiled for Linux and macOS on amd64/arm64. Reports from real use on Linux and macOS are especially welcome.

---

## Development

```sh
go build ./...
go vet ./...
go test -race ./...                 # -race is not optional here
go test ./internal/render -update    # regenerate golden files
```

The trace hooks can fire concurrently (HTTP/2 streams, Happy Eyeballs), so **`-race` is a requirement, not a nicety**. On Windows it needs cgo — put a C compiler such as mingw-w64 on `PATH` and set `CGO_ENABLED=1`.

The highest-priority regression tests assert the **connection-count invariant**: N cold probes must cost the server exactly N connections, and N warm probes exactly 1. If that breaks, every number the tool prints is meaningless. See `TestColdOpensOneConnectionPerProbe` and `TestWarmReusesOneConnection`.

```
main.go                     entry point: parse → run → exit code
internal/cli/               flags, validation, URL normalisation
internal/probe/             httptrace collection, cold/warm runners, scheduler
internal/stats/             percentiles, mdev, aggregation
internal/render/            table layouts, colour, JSON/CSV
```

Dependencies flow one way only: `render → stats → probe`. `probe` owns every shared data type and imports neither of the others.

Contributions are welcome. Please open an issue before large changes — the [Non-goals](#non-goals) list is deliberate, and a PR that widens the scope is likely to be declined regardless of quality.

## License

MIT — see [LICENSE](LICENSE).

`httping` is GPL-licensed. No code from it is included in tlsping.
