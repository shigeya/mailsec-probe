# CLAUDE.md — mailsec-probe

## Project Overview

A Go CLI tool that externally observes mail-security-related DNS records
(SPF / DMARC / DKIM / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC) for a given
domain and emits structured output with per-feature presence and confidence.

Module path: `github.com/shigeya/mailsec-probe`

See [DESIGN.md](DESIGN.md) for the full design.

## Build & Test

```bash
go build ./...              # build
go test ./...               # unit + golden tests
go vet ./...                # static analysis
golangci-lint run           # lint (required in CI)

go test -tags integration ./...   # tests that hit real DNS / HTTPS
```

## Phase Scope

Phase 2.5 is complete. Phase 3.0 is in planning.

**Implemented**:
- **Phase 1.0** — SPF / DMARC / DKIM (fixed selectors) / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC (AD bit only), json/human output, golden tests
- **Phase 1.5** — SPF→DKIM selector inference, MTA-STS↔MX consistency, DMARC rua HTTPS reachability
- **Phase 2.0** — `--active`: SMTP STARTTLS + certificate observation + DANE/TLSA matching (mtatls probe)
- **Phase 2.5** — `--input` batch mode, TSV output, `--stats` cross-domain aggregation

**Planned**:
- **Phase 3.0** — Introduce DNSSEC chain validation via `github.com/shigeya/dnsdata-go` (separate module, co-developed). Distinguishes BOGUS from INSECURE. `--dnssec-mode ad-only` preserves the legacy behavior. See [DESIGN.md §16](DESIGN.md#16-phase-30-plan--dnssec-validation-via-dnsdata-go) for details.

**Out of scope (until Phase 3.0)** — BIMI VMC validation / strict TLSA Usage 0/2 (trust-anchor) verification / sending mail.
When in doubt, prefer observational neutrality and track the gap with a TODO comment.

## Directory Layout

- `cmd/mailsec-probe/` — entry point
- `internal/cli/` — cobra command definitions + `--input` parser
- `internal/probe/` — observers
  - `dnsclient/` — shared DNS client (TXT / MX / TLSA / DS)
  - `httpfetcher/` — shared HTTPS fetcher (Get + Head)
  - `spf/` `dmarc/` `dkim/` `mx/` `mtasts/` `tlsrpt/` `bimi/` `dnssec/`
  - `mtatls/` — active-only (STARTTLS + DANE)
- `internal/signals/` — Signal / Feature / Report types
- `internal/classifier/` — aggregation layer that flattens probes into Features
- `internal/output/` — formatters (json, human, tsv) + stats aggregation
- `rules/` — embedded YAML (`go:embed`)
  - `dkim_selectors.yaml` — fixed selector set
  - `dkim_selector_inference.yaml` — SPF→selector mapping
- `testdata/` — fixtures, golden (if applicable)
- `docs/` — ARCHITECTURE.md, DKIM_SELECTORS.md

## Coding Conventions

- Go 1.22+ (toolchain up to 1.26 allowed)
- `gofmt`, `goimports` enforced
- `golangci-lint` checked in CI
- Exported types and functions have godoc
- Errors are wrapped with `%w`
- Package names are singular and match the directory name
- Logging uses `log/slog` (Warn or higher by default, `-vv` for Debug)
- Immutable-oriented: Signal/Feature values are not mutated after construction

## Commit Convention

Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
Split commits by feature unit. Run `go build ./... && go test ./...` before each commit.

## Design Principles

1. **Separation of observation and judgment** — observers emit neutral Signals; judgments live in rules/classifier
2. **Non-invasive by default** — DNS queries and HTTPS GET only. SMTP requires `--active`
3. **Externalized rules** — YAML embedded via `go:embed`, overridable with `--rules-dir`
4. **Explicit confidence** — each Feature carries a `status` and `confidence` (0.0–1.0)
5. **JSON-first** — machine-readable output is the primary format

## Ethical Considerations

- **User-Agent**: HTTPS GET identifies as `mailsec-probe/<ver>` (no spoofing)
- **robots.txt**: respected by default even for MTA-STS retrieval (`--respect-robots=true`)
- **Non-invasive observation**: DNS and HTTPS only. Direct SMTP / mail server connections are forbidden
- **Raw key concealment**: DKIM public keys and similar are reduced to hash + length by default.
  `--include-raw` includes the raw TXT
- **Rate limiting**: DNS capped at 50 qps per server, HTTPS at 1 req/s per host

## Testing

- Unit tests + golden tests (at least 4 domain cases)
- Tests that depend on external networks live behind the `//go:build integration` tag
- Test files use the `_test.go` suffix
- The DNS client is interface-based so tests can inject a mock
- The HTTP client is likewise interface-based and swappable with fixtures

## Key Technical Decisions

- DNS: `miekg/dns` (direct queries, `--dns-server` supported)
- HTTP: standard `net/http`
- YAML: `gopkg.in/yaml.v3`
- CLI: `cobra` + `viper`
- Concurrency: `golang.org/x/sync/errgroup`
- DNSSEC validation (Phase 3.0): `github.com/shigeya/dnsdata-go` (separate module, co-developed)
- Single binary, no CGO required

## DKIM Selector Strategy

Phase 1.0 uses **a fixed selector set only**. `rules/dkim_selectors.yaml` embeds
common selectors (google, s1, selector1, k1, protonmail, fm1 …); additional
selectors can be added with `--dkim-selector <name>` or the whole set replaced
with `--dkim-selectors-file`.

To distinguish "not configured" from "no selector matched", the DKIM Feature
details always retain `selectors_tried` and `selectors_found`.

Phase 1.5 added inference of likely selectors from the SPF record
(e.g., `include:_spf.google.com` → try `google`).
