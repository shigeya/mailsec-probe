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
              │       internal/cli           │  cobra root, flags, exit codes
              └──────────────┬───────────────┘
                             │
              ┌──────────────▼───────────────┐
              │   internal/classifier        │  fan-out probes per domain
              └──────────────┬───────────────┘
                  │          │          │
        ┌─────────▼┐   ┌─────▼────┐ ┌──▼─────┐
        │ spf      │   │ dmarc    │ │ dkim   │  ← internal/probe/*
        │ mx       │   │ mta-sts  │ │ bimi   │
        │ tls-rpt  │   │ dnssec   │ │        │
        └─────┬────┘   └─────┬────┘ └───┬────┘
              │              │          │
              └──────────────┼──────────┘
                             │
              ┌──────────────▼───────────────┐
              │  internal/probe/dnsclient    │  miekg/dns wrapper + Mock
              │  net/http (mta-sts only)     │
              └──────────────────────────────┘
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
    Run(ctx context.Context, domain string) signals.Feature
}
```

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

- a small interface (`LookupTXT`, `LookupMX`, `HasDS`)
- per-server failover
- automatic UDP → TCP fallback when the server sets the TC bit
- EDNS0 with DO=1 plus an explicit AD-bit request on every query, so
  the resolver's DNSSEC validation status propagates into our
  observations
- a `Mock` implementation in the same package, used by every probe's
  unit tests

The MTA-STS probe additionally needs HTTPS; it accepts an
`HTTPFetcher` interface that tests can stub.

## Output

```
internal/output/json.go   → encoding/json with 2-space indent
internal/output/human.go  → tree-style ASCII summary
```

The human formatter inspects each `Feature.Details` for the
`output.Summarizer` interface (a single `Summary() string` method) and
falls back to the first reason when no summary is provided.

## Concurrency

- The CLI fans out across domains using `errgroup` with `--concurrency`.
- Within a domain, every probe runs in parallel.
- DKIM internally fans out across its selector list (`SetLimit(8)`).
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
