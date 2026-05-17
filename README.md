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
| SPF       | `TXT @ <domain>` starting with `v=spf1` | Detects `-all`/`~all`/`?all`/`+all`, includes, redirect     |
| DMARC     | `TXT @ _dmarc.<domain>`                  | `p=`, `sp=`, `pct=`, `rua=`, `ruf=`, `aspf=`, `adkim=`      |
| DKIM      | `TXT @ <selector>._domainkey.<domain>`   | Probes a curated selector list (extend with `--dkim-selector`) |
| MX        | `MX @ <domain>`                          | Hosts sorted by preference                                  |
| MTA-STS   | `TXT @ _mta-sts.<domain>` + HTTPS policy | Two-stage check; mode=enforce / testing / none              |
| TLS-RPT   | `TXT @ _smtp._tls.<domain>`              | Reports `rua=` endpoint                                     |
| BIMI      | `TXT @ default._bimi.<domain>`           | Reads `l=` (logo) and `a=` (VMC URI); does NOT validate VMC |
| DNSSEC    | AD bit + DS in parent                    | No on-the-wire DNSKEY validation (Phase 1 design choice)    |

## How confidence works

Each feature returns a `Status` and a `Confidence` in `[0, 1]`:

- `present`  — record was found and parses cleanly
- `absent`   — no matching record was observed
- `unknown`  — observation failed (network, timeout, NXDOMAIN ambiguity)
- `misconfigured` — record exists but contradicts itself, lacks required tags, or weakens protection (e.g. SPF `+all`, MTA-STS `mode=none`)

DKIM is the only feature where `absent` is heuristic: we can only
report "no key found at any of the N selectors we tried." Extend the
list with `--dkim-selector <name>` if you know the domain uses
something unusual.

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
    --timeout duration              per-domain observation timeout  (default 10s)
    --concurrency int               max parallel domains  (default 8)
    --include-raw                   include raw TXT/HTTPS bodies in output
-v, --verbose count                 -v info, -vv debug
```

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

See [DESIGN.md](DESIGN.md) for the full architecture and Phase roadmap,
and [CLAUDE.md](CLAUDE.md) for the developer guide.

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

Currently **Phase 1.0 MVP**. Out of scope for this phase:

- SMTP / STARTTLS / DANE-TLSA validation (Phase 2 `--active`)
- SPF-driven DKIM selector inference (Phase 1.5)
- On-the-wire DNSKEY/DS chain validation
- Batch input (`--input domains.txt`) and TSV output (Phase 2.5)
- BIMI VMC (Verified Mark Certificate) validation

## License

MIT. See [LICENSE](LICENSE).
