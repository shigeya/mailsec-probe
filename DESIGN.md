# mailsec-probe — Design Document

## 1. Overview

A Go CLI tool that **externally observes** mail-security DNS records and
public policies (MTA-STS) for a given domain, and returns structured results
covering the presence, health, and confidence of each feature.

- Module path (proposed): `github.com/shigeya/mailsec-probe`
- Binary name: `mailsec-probe`
- Language: Go 1.22+ / single binary / no CGO

## 2. Design Philosophy

1. **Separation of observation and judgment** — observers emit neutral Signals; the rules engine produces judgments
2. **Non-invasive by default** — DNS queries and HTTPS GET only; SMTP connections require `--active`
3. **Externalized rules** — YAML embedded via `go:embed`, overridable with `--rules-dir`
4. **Explicit confidence** — every feature carries `present / absent / unknown` plus a confidence (0.0–1.0)
5. **JSON-first** — machine-readable output is primary; the human format is a subset

## 3. What We Observe (Phase 1 = MVP)

| # | Feature | Observation point | Key interpretation |
|---|---------|-------------------|---------------------|
| 1 | **SPF** | `TXT @ <domain>` matching `v=spf1 ...` | mechanisms, qualifier (`-all`/`~all`/`?all`/`+all`), include/redirect chain |
| 2 | **DMARC** | `TXT @ _dmarc.<domain>` matching `v=DMARC1; ...` | `p=` (none/quarantine/reject), `sp=`, `pct=`, `rua=`, `ruf=`, `aspf=`, `adkim=` |
| 3 | **DKIM** | `TXT @ <selector>._domainkey.<domain>` matching `v=DKIM1; ...` | key type (rsa/ed25519), key size, `t=`, `s=` |
| 4 | **MX** | `MX @ <domain>` | host list ordered by preference |
| 5 | **MTA-STS** | `TXT @ _mta-sts.<domain>` + `https://mta-sts.<domain>/.well-known/mta-sts.txt` | `id=`, `mode=` (enforce/testing/none), `mx:`, `max_age` |
| 6 | **TLS-RPT** | `TXT @ _smtp._tls.<domain>` matching `v=TLSRPTv1; ...` | `rua=` (mailto/https) |
| 7 | **BIMI** | `TXT @ default._bimi.<domain>` matching `v=BIMI1; ...` | `l=` (logo SVG URI), `a=` (VMC URI) |
| 8 | **DNSSEC** | AD bit in the response, presence of DS | whether the zone is signed |

### Out of scope (not implemented in Phase 1)

- STARTTLS / certificate / cipher-suite inspection via real SMTP connections
- DANE/TLSA validation
- Checking that MX entries declared in the MTA-STS policy match the actual MX
  **on the SMTP side** (DNS- and HTTPS-level consistency is in the MVP)
- Key-rotation history
- Bulk processing (CSV/JSON file input)
- Bayesian score fusion (planned later in `internal/classifier`)

## 4. Handling DKIM (the hardest design problem)

DKIM records live at `<selector>._domainkey.<domain>`, so observation is
impossible **without knowing the selector**. DNS does not let you enumerate
all selectors.

### Approach taken

1. **Probe a default selector set** — empirically common ones:
   `google`, `s1`, `s2`, `selector1`, `selector2`, `k1`, `k2`,
   `mail`, `default`, `dkim`, `mandrill`, `mxvault`, `everlytickey1`,
   `everlytickey2`, `protonmail`, `protonmail2`, `protonmail3`,
   `mlsend`, `zoho`, `fm1`, `fm2`, `fm3` …
   → externalized as `rules/dkim_selectors.yaml`, override with `--dkim-selectors`
2. **User-specified** — `--dkim-selector <name>` (repeatable)
3. **Inference from MX/SPF** — e.g., SPF containing `include:_spf.google.com`
   bumps the `google` selector to the front. Implemented in Phase 1.5.
4. **Explicit observation outcome** — "unknown - no selector matched" is an
   acceptable result; do not falsely declare "DKIM not configured".
   Confidence is 0.0 for `unknown`, around 0.5 for `absent (all known selectors tried)`.

### Output example (DKIM)
```json
{
  "feature": "dkim",
  "status": "present",
  "confidence": 0.95,
  "details": {
    "selectors_tried": ["google", "s1", "selector1", "k1"],
    "selectors_found": ["google"],
    "records": [
      {
        "selector": "google",
        "key_type": "rsa",
        "key_size": 2048,
        "raw": "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."
      }
    ]
  }
}
```

## 5. CLI Specification

### Subcommands / invocation

```
mailsec-probe <domain>                       # observe a single domain
mailsec-probe <d1> <d2> ...                  # multiple domains (each run concurrently)
mailsec-probe --input list.txt               # read from a file
mailsec-probe --input - < list.txt           # read from stdin
```

### Main flags (implemented)

| Flag | Default | Purpose |
|------|---------|---------|
| `--output, -o` | `human` | `human` / `json` / `tsv` |
| `--color` | `auto` | `auto` / `always` / `never` (respects `NO_COLOR`) |
| `--input` | (none) | domain list file (`-` for stdin); merged and deduplicated with positional args |
| `--stats` | `false` | append cross-domain statistics (supported by human/tsv/json) |
| `--dns-server` | system resolver | explicit resolver such as `1.1.1.1:53` |
| `--dkim-selector` | (none, repeatable) | extra selectors to try |
| `--dkim-selectors-file` | (embedded YAML) | replace the selector set |
| `--no-spf-inference` | `false` | disable SPF-derived DKIM selector inference |
| `--no-rua-check` | `false` | disable HTTPS HEAD reachability check for DMARC `rua=` |
| `--timeout` | `10s` | per-observation timeout |
| `--concurrency` | `8` | cross-domain parallelism |
| `--include-raw` | `false` | include raw TXT strings in output |
| `--active` | `false` | enable SMTP STARTTLS + DANE active probe |
| `--smtp-port` | `25` | SMTP port for the active probe |
| `--smtp-timeout` | `10s` | per-MX SMTP timeout |
| `--ehlo-name` | `mailsec-probe.local` | name used in EHLO |
| `-v`, `-vv` | Warn / Debug | slog level |

### Exit codes (implemented)

- `0` — every domain produced at least some Feature
- `1` — observation itself failed for some domain (e.g., every Feature was unknown)
- `2` — flag parsing error

## 6. Directory Layout (implemented)

```
cmd/mailsec-probe/         entry point (main.go)
internal/cli/              cobra command definitions + --input parser
internal/probe/            observers
  dnsclient/                 shared DNS client (TXT / MX / TLSA / DS) + Mock
  httpfetcher/               shared HTTPS fetcher (Get + Head) — used by mtasts and dmarc
  spf/                       fetches TXT @ apex and extracts v=spf1
  dmarc/                     TXT @ _dmarc.<d> + rua= HTTPS HEAD
  dkim/                      fixed selector loop + SPF inference
  mx/                        MX records (RFC 7505 null MX aware)
  mtasts/                    DNS TXT + HTTPS GET + MX consistency
  tlsrpt/                    TXT @ _smtp._tls.<d>
  bimi/                      TXT @ default._bimi.<d>
  dnssec/                    AD bit / DS
  mtatls/                    (active-only) STARTTLS + cert + DANE/TLSA
  txttag/                    shared parser for tag=value TXT records
internal/signals/          neutral Signal types
internal/classifier/       flattens probe output and assembles the Report
internal/output/           human / json / tsv formatters + stats + color
rules/                     embedded YAML
  dkim_selectors.yaml             fixed selector set
  dkim_selector_inference.yaml    SPF→selector mapping
testdata/                  fixtures + golden (classifier/testdata)
docs/
  ARCHITECTURE.md            layers / types / how to add a probe
  DKIM_SELECTORS.md          rationale and current state of the selector strategy
```

## 7. Signal Type and Feature Judgment

### Signal (observation, neutral)

```go
type Signal struct {
    Source   string            // "dns_txt" / "https_get" / "dns_mx"
    Target   string            // query target (FQDN, URL)
    OK       bool              // did the fetch itself succeed?
    Records  []string          // raw record list
    Meta     map[string]string // RCODE, AD bit, HTTP status, etc.
    Err      string            // reason when OK=false
}
```

### Feature (after judgment)

```go
type Feature struct {
    Name       string   // "spf" / "dmarc" / "dkim" / "starttls" / "dane" / ...
    Status     Status   // "present" / "absent" / "unknown" / "misconfigured"
    Confidence float64  // 0.0–1.0
    Reasons    []string // why this conclusion was reached (human-readable)
    Details    any      // per-feature structured detail (defined by each probe)
    Signals    []Signal // observations that produced the judgment
}
```

### Probe interface

```go
type Probe interface {
    Name() string
    Run(ctx context.Context, domain string) []signals.Feature  // can return multiple Features
}
```

Most probes return a single-element slice. `mtatls` returns two Features
(`starttls` and `dane`) from a single SMTP session.

### Final result

```go
type Report struct {
    Domain    string
    QueriedAt time.Time
    Features  []Feature
    Errors    []string // fatal errors during observation
}
```

## 8. Rule Shape (YAML)

Example: `rules/dmarc_health.yaml`

```yaml
feature: dmarc
rules:
  - id: dmarc-reject
    when: { tag: p, equals: reject }
    set: { health: strong, confidence_delta: +0.1 }
  - id: dmarc-quarantine
    when: { tag: p, equals: quarantine }
    set: { health: moderate }
  - id: dmarc-none
    when: { tag: p, equals: none }
    set: { health: weak, reason: "monitor-only policy" }
  - id: dmarc-no-rua
    when: { tag: rua, missing: true }
    set: { reason: "no aggregate reporting endpoint" }
```

Rules are implemented as pure functions that take the observed values and
incrementally update a Feature's `Status` / `Confidence` / `Details`.

## 9. Concurrency

- Across domains: `errgroup` parallelism bounded by `--concurrency`
- Within a domain: 8 features run in parallel via `errgroup` (7 DNS queries + 1 HTTPS)
- DKIM additionally fans out over its selector set (up to 8 in parallel)
- The DNS client wraps a shared cache (`internal/probe/dns`) used by every feature

## 10. Ethical Considerations

- **User-Agent**: HTTPS GET identifies as `mailsec-probe/<ver>`
- **robots.txt**: `--respect-robots=true` (default)
- **Non-invasive**: DNS and HTTPS only; SMTP requires `--active`
- **Raw record concealment**: DKIM public keys and similar are long and look
  raw, so they default to hash + length only; `--include-raw` includes the raw TXT
- **Rate limits**: DNS capped at 50 qps per server, HTTPS at 1 req/s per host

## 11. Testing Strategy

- Unit: per-probe parsers in `_test.go`
- Golden: place DNS mocks and expected JSON under `testdata/domains/<name>/`,
  covering at least the following domain archetypes:
  - `google.com`-like (full SPF/DMARC/DKIM/MTA-STS)
  - `<no-mx>.example`-like (no MX)
  - `<spf-only>.example` (SPF present but no DMARC)
  - `<dmarc-none>.example` (only DMARC p=none)
- Integration: `//go:build integration` hits real DNS / real HTTPS; runs as a separate CI job
- The DNS client is interface-based so tests can inject a mock

## 12. Output Example (human)

```
$ mailsec-probe example.jp

example.jp
├─ SPF       PRESENT      conf=0.95   v=spf1 include:_spf.example.jp ~all
├─ DMARC     PRESENT      conf=0.95   p=quarantine; rua=mailto:dmarc@example.jp
├─ DKIM      PRESENT      conf=0.90   selectors: google, selector1
├─ MX        PRESENT      conf=1.00   10 mx1.example.jp., 20 mx2.example.jp.
├─ MTA-STS   PRESENT      conf=0.90   mode=enforce, max_age=604800
├─ TLS-RPT   ABSENT       conf=0.80   no TXT at _smtp._tls.example.jp
├─ BIMI      ABSENT       conf=0.80   no TXT at default._bimi.example.jp
└─ DNSSEC    PRESENT      conf=1.00   AD bit set, DS in parent
```

## 13. Output Example (JSON, excerpt)

```json
{
  "domain": "example.jp",
  "queried_at": "2026-05-17T09:30:00+09:00",
  "features": [
    {
      "name": "spf",
      "status": "present",
      "confidence": 0.95,
      "reasons": ["v=spf1 found at apex", "qualifier=~all (softfail)"],
      "details": {
        "qualifier": "softfail",
        "includes": ["_spf.example.jp"],
        "raw": "v=spf1 include:_spf.example.jp ~all"
      }
    }
  ]
}
```

## 14. Development Phases (current: Phase 2.5 complete)

| Phase | Status | Scope |
|-------|--------|-------|
| **1.0** | ✅ implemented | SPF / DMARC / DKIM (fixed selectors) / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC (AD bit only), json/human output, golden tests |
| **1.5** | ✅ implemented | SPF → DKIM selector inference (`--no-spf-inference` to disable), DMARC `rua=` HTTPS HEAD reachability (`--no-rua-check`), consistency between MTA-STS policy `mx:` patterns and the actual MX |
| **2.0** | ✅ implemented | `--active`: SMTP STARTTLS / certificate observation / PKIX verification / DANE/TLSA matching (Usage 3 = DANE-EE is strict; Usage 0/2 is observe-only) |
| **2.5** | ✅ implemented | `--input <file>` batch mode (`-` for stdin), `--output tsv`, `--stats` cross-domain aggregation, ANSI color output (`--color auto\|always\|never`) |
| **3.0** | ✅ implemented | DNSSEC chain validation via `github.com/shigeya/dnsdata-go` v0.2.2. Default is `--dnssec-mode validate` (chain validation); the Phase 1.0 AD-bit-only mode survives as `--dnssec-mode ad-only`. See §16 |
| **3.x** | candidates | See §17 below |

### Findings from Phase 1.5

- example.com (IANA) returns a `v=DKIM1; p=` wildcard for `<any>._domainkey.example.com` → reclassified as ABSENT (revoked wildcard)
- example.com publishes RFC 7505 null MX (`0 .`) → added a `null MX` guard to the MX feature
- Google has revoked every old DKIM selector (`20161025` / `20210112` / `20221208` / `20230601`) — confirming the reality of selector rotation; we must keep adding fresh candidates to `rules/dkim_selector_inference.yaml`

### Findings from Phase 2.0

- nlnetlabs.nl (backed by mailbox.org) passes TLSA validation on all 3 MX with DANE-EE; adopted as an integration-test example
- google.com is MTA-STS enforce / TLS 1.3 / PKIX valid but does not deploy DANE
- DANE adoption remains low; major providers (Fastmail / Google) do not deploy it

## 15. Decisions (locked in during implementation)

| # | Item | Decision |
|---|------|----------|
| 1 | Tool / binary name | `mailsec-probe` |
| 2 | Module path | `github.com/shigeya/mailsec-probe` |
| 3 | DKIM selector strategy | Fixed set + SPF inference (Phase 1.5 implemented) |
| 4 | DNSSEC | AD bit + DS only in Phase 1.0–2.5. Phase 3.0 introduces chain validation via `dnsdata-go` and distinguishes BOGUS from INSECURE |
| 5 | Input unit | Domain only; `user@domain` is rejected |
| 6 | BIMI depth | Up to TXT parsing; VMC validation is a Phase 3 candidate |
| 7 | Output | Three formats: human / json / tsv; `--stats` adds aggregation to each |
| 8 | Ethics | Non-invasive by default; SMTP requires `--active`, EHLO self-identifies, no mail is sent |
| 9 | Probe interface | `Run` returns `[]signals.Feature` (so `mtatls` can emit both `starttls` and `dane` from a single connection) |

## 16. Phase 3.0 Plan — DNSSEC validation via dnsdata-go

### Background

The Phase 1.0 DNSSEC probe observes **only the AD bit and the presence of DS**,
which cannot detect signature failure (BOGUS). In practice, being unable to
distinguish a misconfigured DNSSEC zone from a SECURE one is a weakness for
an observation tool.

In Phase 3.0 we introduce DNSSEC chain validation by **delegating to `dnsdata-go`**.

### Dependency

`github.com/shigeya/dnsdata-go` — a Go DNS / DNSSEC library developed as a
separate module. A pure port of the TypeScript `dnsdata-js` (originating
from wide-cpp-lib) to Go. Co-developed with mailsec-probe (both repos owned
by the same author).

```
mailsec-probe (this repo)
    └─ depends on → github.com/shigeya/dnsdata-go/verifier  (DNSSEC chain validator)
                  → github.com/shigeya/dnsdata-go/dnssec    (DNSKEY/RRSIG/DS primitives)
                  → github.com/shigeya/dnsdata-go/resolver  (DoH / authoritative DNS)
```

### Validation Scope

- **Chain-of-trust validation** starting from the root trust anchors (KSK-2017 + KSK-2024, embedded)
- Result is one of four verdicts: `Secure | Insecure | Bogus | Indeterminate`
- Insecure delegation (DS goes missing partway down the chain) is distinguished from BOGUS

### Requirements on dnsdata-go

The API contract that mailsec-probe (= the consumer) asks `dnsdata-go` to
honor. The same text is transcribed into the `dnsdata-go` DESIGN.md / issues
so it can serve as the co-design north star.

#### MUST

1. `Validate(ctx, qname, qtype) → (*Result, error)` is goroutine-safe
2. `Result.Verdict` is an enum of `Secure | Insecure | Bogus | Indeterminate`
3. `Result.Chain` contains each zone's DNSKEY/DS tags, algorithms, and RRSIG verification results
4. `Result.InsecureAt` / `Result.BogusAt` returns the failure point as a string
5. `Result.Evidence` carries the raw DS/DNSKEY/RRSIG data (forwarded into mailsec-probe Signals)
6. `context.Context` propagates cancel / deadline
7. The trust anchor source is caller-supplied (`WithTrustAnchors(io.Reader)` etc.)
8. DoH providers can be passed as a slice (failover order: Google / Cloudflare / Quad9)
9. There is a direct-to-authoritative-NS mode (to interoperate with mailsec-probe's `--dns-server`)
10. `Result` can be marshaled directly with `encoding/json`
11. `Verdict.String()` returns `"secure"` / `"insecure"` / `"bogus"` / `"indeterminate"`
12. Errors are sentinels usable with `errors.Is` (`ErrNoDS`, `ErrSigExpired`, `ErrUnsupportedAlgo`, `ErrChainTimeout`, ...)

#### SHOULD

13. A pluggable cache layer (`WithCache(c Cache)`) so root/TLD DNSKEY can be reused across a batch run
14. Streamable verification steps (`WithStepHandler(func(StepEvent))`) for verbose logging
15. RR types accepted as `uint16` (compatible with miekg/dns)
16. Memory efficiency acceptable when validating 100 domains in parallel

#### MAY (future)

17. Helper converters to `miekg/dns.RR` (ecosystem interop)
18. Aggressive negative caching with NSEC/NSEC3 (RFC 8198)
19. RFC 5011 automatic trust anchor updates

#### MUST NOT

20. Call `os.Exit`
21. Produce side effects from `init()` (acquiring a logger, etc.)
22. Hold global state (multiple Verifiers must be independent)
23. Write to the filesystem by default (only touch `~/.dnsdata-go/` etc. when explicitly told to)
24. Write to stdout / stderr (the caller routes output to their logger of choice)

### Sketch of the new dnssec probe API (mailsec-probe side)

```go
// internal/probe/dnssec/dnssec.go (planned after Phase 3.0)
package dnssec

import (
    "context"

    "github.com/miekg/dns"
    "github.com/shigeya/dnsdata-go/verifier"
    "github.com/shigeya/mailsec-probe/internal/signals"
)

type Probe struct {
    V *verifier.Verifier
}

func New(v *verifier.Verifier) *Probe { return &Probe{V: v} }

func (*Probe) Name() string { return "dnssec" }

func (p *Probe) Run(ctx context.Context, domain string) []signals.Feature {
    r, err := p.V.Validate(ctx, domain+".", dns.TypeTXT)
    if err != nil {
        // StatusUnknown + Reasons with err.Error()
    }
    switch r.Verdict {
    case verifier.Secure:
        // StatusPresent, confidence 0.95
        // Reasons: "DNSSEC chain validated from root"
    case verifier.Insecure:
        // StatusAbsent, confidence 0.9
        // Reasons: "insecure delegation at <r.InsecureAt>"
    case verifier.Bogus:
        // StatusMisconfigured, confidence 0.95
        // Reasons: "BOGUS at <r.BogusAt>: <r.BogusReason>"
    case verifier.Indeterminate:
        // StatusUnknown
    }
    // convert r.Evidence into Signal[]
    // store r.Chain in Details
}
```

### Extending `signals.Status`

Phase 3.0 adds **`StatusMisconfigured`** to `internal/signals/signals.go`.
Beyond DNSSEC BOGUS, it will also be reusable for MTA-STS policy/MX
mismatches, DKIM key-length deficiencies, and similar cases in the future.

### Impact on the CLI

- New flag `--dnssec-mode {ad-only,validate}` (default `validate`)
  - `ad-only` preserves Phase 1.0 behavior (AD bit + DS only)
  - `validate` performs chain validation via dnsdata-go
- New flag `--dnssec-doh-providers google,cloudflare,quad9` (defaults to all three in sequence)
- When `--dns-server` is explicitly set, dnsdata-go automatically switches to direct authoritative-NS queries

### Impact on golden tests

The `dnssec` Feature in `testdata/domains/<name>/golden.json` will change and
needs to be regenerated. We will prepare matching `testdata/` (chain-validated
DNS response fixtures) on the dnsdata-go side and share the same fixtures
across mailsec-probe via the Mock DNS / Mock DoH layer.

### Schedule estimate

| Week | dnsdata-go side | mailsec-probe side |
|------|------------------|---------------------|
| Week 1 | repo bootstrap; minimal `types/`, `wire/` + tests (`zone/` slipped to Week 2) | (none) |
| Week 2 | `zone/`, full `dnssec/` (DNSKEY/RRSIG/DS/NSEC/anchors), `resolver/doh/` | (none) |
| Week 3 | `verifier/chain.go` (chain walker), `v0.1.0` tag | (none) |
| Week 4 | NSEC / NSEC3 negative-proof primitives, six-state Verdict, `v0.2.0` tag | (none) |
| Week 5 | CNAME / DNAME chasing, `Result.Aliases` | (none) |
| Week 6 | Wildcard-synthesised positive answers, `Result.Wildcard` | (none) |
| Week 7 | `v0.2.1` — `resolver/{doh,auth}.Resolve` surfaces authority section so NSEC/NSEC3 proofs reach the verifier | `--dnssec-mode {ad-only,validate}` wired through `internal/probe/dnssec/`, default = `validate`, Verdict → Status mapping |
| Week 7.1 | `v0.2.2` — `verifier/chain.go` no-cut descent fix (issue #1): chain walk no longer terminates at the first non-cut intermediate label, so signed names under multi-label TLDs (`*.ad.jp`, `*.co.jp`, `*.ne.jp`, …) validate as `Secure` instead of misreporting `Bogus` | bump dependency; `wide.ad.jp` and friends now report `DNSSEC PRESENT / secure` under the default `validate` mode |

For progress sharing and session ownership, see the `dnsdata-go` repo's CLAUDE.md / DESIGN.md.

## 17. Phase 3.x and Beyond — Candidates (unstarted)

- **BIMI VMC validation** — fetch the VMC from the `a=` URI, extract the key as x509, and verify the BIMI Indicator authentication chain
- **STARTTLS cipher-suite evaluation** — downgrade weak ciphers / TLS 1.0/1.1 acceptance to `misconfigured`
- **MTA-STS reporter-side testing** — provide an endpoint that actually consumes TLS-RPT reports
- **DKIM key weakness checks** — push 1024-bit RSA and exponent=3 toward `misconfigured`
- **Shared DNS cache** — avoid duplicate TXT lookups across the SPF probe and DKIM inference (currently 2 TXT queries per domain)
- **CI (GitHub Actions + `golangci-lint`)** — alongside making the repo public
- **Strict TLSA Usage 0 / 2 (trust-anchor) verification** — currently judged solely on leaf cert hash match regardless of Usage
