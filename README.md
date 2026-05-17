# mailsec-probe

Observe a domain's mail-security DNS records (SPF / DMARC / DKIM / MX /
MTA-STS / TLS-RPT / BIMI / DNSSEC) from the outside, and report each
feature's status, confidence, and structured details.



## Why

> "Does this domain enforce DMARC? Are they on MTA-STS yet? Which DKIM
> selector are they signing with? Is the zone DNSSEC-signed?"

`mailsec-probe` answers those questions in seconds, with a single
non-invasive scan that touches only DNS and (for MTA-STS) HTTPS — no
SMTP, no probing of the target's mail servers.

The output is JSON-first so it composes naturally with `jq`, CI scripts,
and follow-up tooling. A human-readable view is also provided.

## Install

Requires Go 1.22 or newer.

```bash
go install github.com/shigeya/mailsec-probe/cmd/mailsec-probe@latest
```

Or build from a clone:

```bash
git clone https://github.com/shigeya/mailsec-probe.git
cd mailsec-probe
go build ./cmd/mailsec-probe
./mailsec-probe example.com
```

## Quick start

```console
$ mailsec-probe cloudflare.com
cloudflare.com
├─ SPF        PRESENT       conf=0.95   qualifier=fail
├─ DMARC      PRESENT       conf=0.95   p=reject
├─ DKIM       PRESENT       conf=0.95   DKIM key(s) at: k1, krs, mandrill, s1, smtpapi
├─ MX         PRESENT       conf=1.00   4 MX record(s)
├─ MTA-STS    ABSENT        conf=0.90   no _mta-sts TXT and no HTTPS policy
├─ TLS-RPT    ABSENT        conf=0.90   no v=TLSRPTv1 TXT at _smtp._tls.cloudflare.com
├─ BIMI       PRESENT       conf=0.90   v=BIMI1
└─ DNSSEC     PRESENT       conf=1.00   DS present in parent zone
```

JSON output (for pipelines):

```bash
mailsec-probe -o json example.com | jq '.features[] | select(.status=="present") | .name'
```

Multiple domains run in parallel:

```bash
mailsec-probe -o json google.com cloudflare.com github.com > scan.json
```

## What it checks

| Feature   | DNS record                              | Notes                                                       |
|-----------|------------------------------------------|-------------------------------------------------------------|
| SPF       | `TXT @ <domain>` starting with `v=spf1` | Detects `-all`/`~all`/`?all`/`+all`, includes, redirect (`redirect=` without `all` is valid, RFC 7208 §6.1) |
| DMARC     | `TXT @ _dmarc.<domain>`                  | `p=`, `sp=`, `pct=`, `rua=`, `ruf=`, `aspf=`, `adkim=`      |
| DKIM      | `TXT @ <selector>._domainkey.<domain>`   | Probes a curated selector list; honours `v=DKIM1; p=` revocations and revoked-wildcard patterns (see [docs/DKIM_SELECTORS.md](docs/DKIM_SELECTORS.md)) |
| MX        | `MX @ <domain>`                          | Hosts sorted by preference; `MX 0 .` (RFC 7505 null MX) is reported as absent with the explicit reason |
| MTA-STS   | `TXT @ _mta-sts.<domain>` + HTTPS policy | Two-stage check; mode=enforce / testing / none              |
| TLS-RPT   | `TXT @ _smtp._tls.<domain>`              | Reports `rua=` endpoint                                     |
| BIMI      | `TXT @ default._bimi.<domain>`           | Reads `l=` (logo) and `a=` (VMC URI); does NOT validate VMC |
| DNSSEC    | AD bit + DS in parent                    | No on-the-wire DNSKEY validation (Phase 1 design choice)    |
| STARTTLS  | `EHLO` + STARTTLS + TLS handshake on each MX:25 | **Active**: opt-in via `--active`. Records TLS version, leaf cert subject/issuer/SANs/expiry, PKIX validity |
| DANE      | `TLSA @ _25._tcp.<mx>` matched against observed cert | **Active**: usage/selector/matching parsed; SHA-256 / SHA-512 of full-cert or SPKI checked against the cert returned during STARTTLS |

## How confidence works

Each feature returns a `Status` and a `Confidence` in `[0, 1]`:

- `present`  — record was found and parses cleanly
- `absent`   — no matching record was observed
- `unknown`  — observation failed (network, timeout, NXDOMAIN ambiguity)
- `misconfigured` — record exists but contradicts itself, lacks required tags, or weakens protection (e.g. SPF `+all`, MTA-STS `mode=none`)

DKIM is the only feature where `absent` is heuristic: we can only
report "no key found at any of the N selectors we tried." Extend the
list with `--dkim-selector <name>` if you know the domain uses
something unusual. The DKIM probe also distinguishes RFC 6376
revocation (`v=DKIM1; p=`) from a live key, and recognises the
revoked-wildcard pattern used by e.g. `example.com`. See
[docs/DKIM_SELECTORS.md](docs/DKIM_SELECTORS.md) for the full
strategy and current limitations.

## DKIM selector strategy

DKIM keys live at `<selector>._domainkey.<domain>` and there is no DNS
mechanism to enumerate selectors. `mailsec-probe` bundles a curated list
covering Google Workspace, Microsoft 365, Amazon SES, Mandrill,
SendGrid, Mailgun, Postmark, Fastmail, ProtonMail, Zoho, MailerSend,
and common generic names (`default`, `selector1`, `s1`, `k1`, ...).

```bash
# add custom selectors
mailsec-probe --dkim-selector my-corp1 --dkim-selector my-corp2 example.com

# replace the embedded list entirely
mailsec-probe --dkim-selectors-file ./selectors.yaml example.com
```

The YAML format mirrors `rules/dkim_selectors.yaml`.

## Flags

```
-o, --output string                 output format: human|json  (default "human")
    --dns-server string             DNS server (host or host:port). Default: system resolver
    --dkim-selector strings         additional DKIM selector to probe (repeatable)
    --dkim-selectors-file string    override embedded DKIM selector list
    --no-spf-inference              disable SPF-driven DKIM selector inference
    --no-rua-check                  disable DMARC rua= HTTPS reachability HEAD checks
    --active                        enable active SMTP probes (STARTTLS + DANE) on each MX:25
    --smtp-port int                 SMTP port for --active probes (default 25)
    --smtp-timeout duration         per-MX SMTP probe timeout (default 10s)
    --ehlo-name string              EHLO name used during --active probes (default "mailsec-probe.local")
    --timeout duration              per-domain observation timeout  (default 10s)
    --concurrency int               max parallel domains  (default 8)
    --include-raw                   include raw TXT/HTTPS bodies in output
-v, --verbose count                 -v info, -vv debug
```

## Active mode (`--active`)

By default `mailsec-probe` only reads DNS and a single HTTPS file
(MTA-STS). With `--active` it additionally opens TCP connections to
each MX host on port 25 and talks SMTP up to and including the TLS
handshake:

```console
$ mailsec-probe --active nlnetlabs.nl
nlnetlabs.nl
├─ SPF        PRESENT       conf=0.95   qualifier=softfail, 2 includes
├─ DMARC      PRESENT       conf=0.95   p=none, rua
├─ DKIM       PRESENT       conf=0.95   default, google (rsa 1024-bit)
├─ MX         PRESENT       conf=1.00   10 mxext1.mailbox.org, 10 mxext2.mailbox.org, +1 more
├─ STARTTLS   PRESENT       conf=0.90   3/3 MX STARTTLS, 3/3 PKIX-valid (TLS 1.3)
├─ DANE       PRESENT       conf=0.95   3/3 MX have TLSA, 3/3 validate
├─ MTA-STS    ABSENT        conf=0.90   no _mta-sts TXT and no HTTPS policy
├─ TLS-RPT    ABSENT        conf=0.90   no v=TLSRPTv1 TXT at _smtp._tls.nlnetlabs.nl
├─ BIMI       ABSENT        conf=0.85   no v=BIMI1 TXT at default._bimi.nlnetlabs.nl
└─ DNSSEC     PRESENT       conf=1.00   DS + AD
```

The active probe:

- never sends mail
- identifies itself in the EHLO greeting (default `mailsec-probe.local`,
  override with `--ehlo-name`)
- uses a tight per-MX timeout (10 s default)
- only ever connects once per MX, even when multiple A records exist
- reports cert chain summary (subject, issuer, SANs, NotAfter, PKIX validity)
- compares each TLSA record at `_25._tcp.<mx>` against the live cert
  using SHA-256 / SHA-512 over the full certificate or the SPKI

Active mode requires outbound TCP :25 to work. Many residential
networks and CI runners block it; in those environments STARTTLS will
come back as `UNKNOWN` and DANE will be `ABSENT` (no TLSA observable).

## Exit codes

- `0` — all domains observed (regardless of feature presence)
- `1` — at least one domain failed observation outright (DNS unreachable etc.)
- `2` — invalid flags or arguments

## Ethics

`mailsec-probe` is non-invasive by design:

- DNS queries and a single HTTPS GET to `https://mta-sts.<domain>/.well-known/mta-sts.txt`. Nothing else.
- No SMTP connections, no STARTTLS probes, no authentication attempts.
- User-Agent identifies itself honestly as `mailsec-probe/<version>`.
- DKIM public keys and other raw records are omitted from output unless
  you opt in with `--include-raw`.

## Design

- [DESIGN.md](DESIGN.md) — product spec and phase roadmap
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — internal layering, type
  contracts, and how to add a new probe
- [docs/DKIM_SELECTORS.md](docs/DKIM_SELECTORS.md) — DKIM strategy
  rationale and limits
- [CLAUDE.md](CLAUDE.md) — developer guide

The high-level layering is:

```
probes  ->  signals (neutral observations)  ->  classifier  ->  Feature{status, confidence, details}
```

Probes never make value judgments; the classifier turns signals into
features.

## Testing

```bash
go test ./...                            # unit + golden tests (no network)
go test -tags integration ./...          # also exercises real DNS / HTTPS
```

The integration tests query a small set of well-known domains
(google.com, cloudflare.com, example.com) and assert the *shape* of
their mail-security setup rather than exact values, so they tolerate
the upstream operators rotating records.

## Phase

Currently **Phase 2.0**. Phase 2.0 adds the `--active` SMTP probe set:

- **STARTTLS** — connect to each MX on :25, EHLO, STARTTLS, observe
  TLS version and certificate chain
- **DANE / TLSA** — look up TLSA at `_25._tcp.<mx>` and match against
  the cert presented during STARTTLS (Usage/Selector/MatchingType
  combinations 0/0, 1/1, 1/2)

See the [Active mode](#active-mode---active) section above for usage.

Phase 1.5 adds:

- **SPF → DKIM selector inference** (`--no-spf-inference` to disable):
  when SPF includes a recognised provider (Google Workspace, Microsoft
  365, Amazon SES, Mailgun, SendGrid, Mandrill, Postmark, Fastmail,
  ProtonMail, Zoho, MailerSend, ...), provider-specific DKIM
  selectors are added to the probe set per domain.
- **MTA-STS ↔ MX consistency** check: actual MX records are matched
  against the policy's `mx:` patterns (including `*.suffix`
  wildcards). A mismatch downgrades the verdict to *misconfigured*.
- **DMARC rua reachability** (`--no-rua-check` to disable): HTTPS rua
  endpoints get a HEAD request; `mailto:` endpoints are noted but
  never probed (out of scope by design).

Out of scope:

- On-the-wire DNSKEY/DS chain validation
- Batch input (`--input domains.txt`) and TSV output (Phase 2.5)
- BIMI VMC (Verified Mark Certificate) validation
- TLSA Usage 0/2 (trust-anchor) semantics — Phase 2.0 validates Usage 3
  (DANE-EE) precisely; trust-anchor records are observed but treated
  the same as DANE-EE for the matching check

## License

MIT. See [LICENSE](LICENSE).
