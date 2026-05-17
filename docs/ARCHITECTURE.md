# Architecture

This document describes the internal layering of `mailsec-probe`. For
the bigger product story see [DESIGN.md](../DESIGN.md); for usage see
[README.md](../README.md).

## Layering

```
              ┌──────────────────────────────┐
              │   cmd/mailsec-probe (main)   │
              └──────────────┬───────────────┘
                             │
              ┌──────────────▼───────────────┐
              │       internal/cli           │  cobra root, --input, flags, exit codes
              └──────────────┬───────────────┘
                             │
              ┌──────────────▼───────────────┐
              │   internal/classifier        │  fan-out probes per domain (flatten []Feature)
              └──────────────┬───────────────┘
                  │          │          │
        ┌─────────▼─┐  ┌─────▼─────┐ ┌──▼──────┐
        │ spf       │  │ dmarc     │ │ dkim    │  ← passive probes
        │ mx        │  │ mta-sts   │ │ bimi    │     internal/probe/*
        │ tls-rpt   │  │ dnssec    │ │ mtatls* │
        └─────┬─────┘  └─────┬─────┘ └────┬────┘
              │              │            │
              └──────────────┼────────────┘
                             │
              ┌──────────────▼───────────────┐
              │  internal/probe/dnsclient    │  miekg/dns + UDP→TCP + TLSA + Mock
              │  internal/probe/httpfetcher  │  HTTPS Get + Head (mtasts + dmarc)
              │  net/smtp + crypto/tls       │  (mtatls only, with --active)
              └──────────────────────────────┘

  * mtatls is an active probe — only wired in when --active is set.
    It emits TWO features per run: "starttls" and "dane".
```

Output is produced by `internal/output` (`json.go`, `human.go`) and
consumed from `internal/cli`.

## Data flow

A single domain scan:

1. `cli.run` builds a `dnsclient.Client` and constructs every `Probe`.
2. `classifier.Runner.Run` invokes every probe in parallel via
   `errgroup`. Each probe is independent and goroutine-safe.
3. Each probe issues one or more **observations** (`Signal`) and
   immediately turns them into a **judgment** (`Feature`).
4. The runner returns a `Report` (domain + features + queried-at +
   optional top-level errors).
5. The output package writes the report(s) as JSON or human text.

There is no mutable shared state between probes. The DNS client is the
only shared resource and is read-only after construction.

## Core types (`internal/signals`)

```go
type Signal struct {
    Source  Source            // "dns_txt" | "dns_mx" | "dns_ds" | "https_get" | ...
    Target  string            // FQDN or URL
    OK      bool              // observation succeeded (not the same as "found anything")
    Records []string          // raw records seen
    Meta    map[string]string // RCODE, AD bit, HTTP status etc.
    Err     string            // populated when OK is false
}

type Feature struct {
    Name       string   // "spf" | "dmarc" | ...
    Status     Status   // present | absent | unknown | misconfigured
    Confidence float64  // 0.0..1.0
    Reasons    []string // human-readable WHY
    Details    any      // feature-specific struct (see each probe's package)
    Signals    []Signal // the observations the verdict was built from
}

type Report struct {
    Domain    string
    QueriedAt time.Time
    Features  []Feature
    Errors    []string  // top-level (e.g. empty domain); probe failures go in Feature.Status=unknown
}
```

The split between `Signal` and `Feature` is the spine of the design.
Probes are the only things that touch the network; the classifier is
the only thing that interprets observations. This keeps the network
layer easy to mock and the judgment layer easy to test in isolation.

## Adding a probe

A `Probe` is anything that satisfies:

```go
type Probe interface {
    Name() string
    Run(ctx context.Context, domain string) []signals.Feature
}
```

Most probes return a single-element slice. The active `mtatls` probe
is the canonical example of a multi-feature return: one SMTP session
per MX produces both a `starttls` and a `dane` feature.

To add one (let's call it `foo`):

1. Create `internal/probe/foo/foo.go` with:
   - a `Probe` struct holding `DNS dnsclient.Client` and any options
   - `New(d dnsclient.Client, ...) *Probe`
   - a `Name() string` method returning `"foo"`
   - a `Run(ctx, domain) signals.Feature` method
   - a `Details` struct serialised into `Feature.Details`
   - optionally a `Summary() string` method on `Details` for the
     human formatter (see `internal/output/human.go`)
2. Write `internal/probe/foo/foo_test.go` against `dnsclient.NewMock()`.
3. Wire the probe into `internal/cli/cli.go` `buildProbes`.
4. Add a feature-order entry to
   `internal/classifier/classifier.go#featureOrder` so the new probe
   shows up where you want in the human output.

The `dnsclient.Mock` exists so probe tests can stay deterministic. No
probe test should hit the real network — those go behind
`//go:build integration` (see `dnsclient_integration_test.go` for the
canonical pattern).

## DNS client

`internal/probe/dnsclient` wraps `github.com/miekg/dns` with:

- a small interface (`LookupTXT`, `LookupMX`, `LookupTLSA`, `HasDS`)
- per-server failover
- automatic UDP → TCP fallback when the server sets the TC bit
- EDNS0 with DO=1 plus an explicit AD-bit request on every query, so
  the resolver's DNSSEC validation status propagates into our
  observations
- a `Mock` implementation in the same package, used by every probe's
  unit tests

`internal/probe/httpfetcher` provides a tiny `Fetcher` interface
(`Get` + `Head`) backed by `net/http`. `mtasts` uses `Get` for the
policy file; `dmarc` uses `Head` for `rua=` reachability checks.

The active `mtatls` probe additionally uses `net/smtp` and `crypto/tls`
through its own `Dialer` interface so tests can stub the SMTP/TLS
handshake without a real socket.

## Output

```
internal/output/json.go   → encoding/json with 2-space indent
internal/output/human.go  → tree-style ASCII summary
internal/output/tsv.go    → tabular "domain\tfeature\tstatus\tconfidence\treason"
internal/output/stats.go  → cross-domain aggregation (--stats)
```

The human formatter inspects each `Feature.Details` for the
`output.Summarizer` interface (a single `Summary() string` method) and
falls back to the first reason when no summary is provided.

`Compute(reports)` produces a `Stats` value keyed by feature name;
`--stats` causes the chosen formatter to append the stats block:

- human: ASCII table after the per-domain trees
- tsv: a `# stats` separator line followed by a second TSV table
- json: top-level shape becomes `{"reports": [...], "stats": {...}}`
  (without `--stats` the shape stays an array or single object,
  preserving backward compatibility)

## Concurrency

- The CLI fans out across domains using `errgroup` with `--concurrency`.
- Within a domain, every probe runs in parallel.
- DKIM internally fans out across its selector list (`SetLimit(8)`)
  and performs an additional SPF lookup for selector inference.
- The active `mtatls` probe fans out across MX hosts (`SetLimit(4)`)
  for both the SMTP handshake and the per-host TLSA lookup.
- All slices are sized up front to avoid concurrent appends.

## Errors and exit codes

Per `internal/cli/cli.go`:

- `0` — every domain produced a `Report` whose features were not all
  unknown
- `1` — at least one domain failed observation outright (e.g. DNS
  unreachable, every probe returned `unknown`)
- `2` — invalid flags or arguments

A probe failure does **not** abort the report; it surfaces as a
`Feature` with `Status=unknown` and a reason explaining why. This way
a partial scan is still useful.
