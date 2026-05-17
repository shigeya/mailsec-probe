# DKIM selector strategy

DKIM keys live at `<selector>._domainkey.<domain>` and the DNS protocol
provides **no way to enumerate selectors** for a zone. This document
explains how `mailsec-probe` works around that, what its current limits
are, and how to extend coverage.

## The fundamental problem

To verify that a domain signs mail with DKIM (RFC 6376) we would need
to know which selector the domain currently uses. That information is
attached to outbound messages in the `DKIM-Signature:` header. A
non-invasive observer that only touches DNS cannot see those headers
and so cannot know the selector authoritatively.

Three workarounds exist:

| Strategy | Coverage | Cost |
|---------|----------|------|
| **Probe a curated default list** (Phase 1.0) | Catches the long tail of mainstream providers | Cheap; one DNS lookup per selector |
| **Infer from SPF includes** (Phase 1.5) | Pulls in provider-specific selectors when the domain uses a recognisable include | One extra parse step |
| **Read mail headers** | Authoritative, but requires receiving mail from the target | Out of scope (would no longer be observation-only) |

`mailsec-probe` is currently at Phase 1.0 — a curated default list.

## The default list

Maintained in [`rules/dkim_selectors.yaml`](../rules/dkim_selectors.yaml)
and embedded at build time via `//go:embed`.

The list groups selectors by upstream provider so the file is easy to
keep current:

- **Generic / placeholder**: `default`, `mail`, `dkim`, `selector1`,
  `selector2`, `s1`, `s2`, `k1`, `k2`
- **Google Workspace**: `google`, `20161025`, `20210112`
- **Microsoft 365 / Outlook**: `selector1-com`, `selector2-com`
- **Amazon SES**: `amazonses` (also commonly uses domain-specific UUIDs
  which are not enumerable)
- **Mandrill / Mailchimp**: `mandrill`, `k3`
- **SendGrid**: `s1024`, `smtpapi`
- **Mailgun**: `mailo`, `mg`, `krs`
- **Postmark**: `20210309165435pm`
- **Fastmail**: `fm1`, `fm2`, `fm3`
- **ProtonMail**: `protonmail`, `protonmail2`, `protonmail3`
- **Zoho**: `zoho`, `zmail`
- **MailerSend / MailerLite**: `mlsend`, `ml1`, `ml2`
- **Mxvault / EveryAction etc.**: `mxvault`, `everlytickey1`, `everlytickey2`
- **Generic backup names**: `smtp`, `mta`, `email`, `dkim1`, `dkim2`

Ordering matters because selector probing is parallel but bounded
(default `SetLimit(8)`): more common selectors come first so an early
hit short-circuits the bulk of the lookups.

## Distinguishing "absent" from "unknown selector"

This is the most subtle part of DKIM probing. Three distinct outcomes
look superficially similar:

| Real-world state | Our verdict | Confidence |
|------------------|-------------|------------|
| Domain does not sign with DKIM | `absent` | 0.5 |
| Domain signs, but the selector is not in our list | `absent` | 0.5 (false negative) |
| Domain signs at a selector we tried | `present` | 0.95 |
| Domain publishes `v=DKIM1; p=` (RFC 6376 explicit revocation) | `absent` | 0.9 |
| Domain publishes a wildcard `v=DKIM1; p=` (e.g. `example.com`) | `absent` | 0.9 |

The lower confidence on the first two cases is honest: we genuinely
cannot tell them apart without out-of-band information. The output
JSON always carries `selectors_tried` so a caller can decide whether
to trust the absent verdict.

### Revoked-wildcard handling

`example.com` is the canonical example: querying ANY `_domainkey`
subdomain there returns `v=DKIM1; p=`. The empty `p=` is RFC 6376's
way to publish a revoked key — "this selector exists but its key has
been retired."

Before the fix added in commit `35784d4`, a wildcard like this caused
`mailsec-probe` to report "DKIM present at 42 selectors." We now treat
all-revoked outcomes as `absent` with a reason that distinguishes a
single revoked selector from a wildcard pattern.

### Selector rotation

Mainstream providers rotate selectors aggressively. Google's
`20161025` and `20210112` (still in our default list) currently both
return revoked records — Google has moved on to newer selectors. The
mitigation today is to keep the YAML file updated; the strategic
mitigation is Phase 1.5 (SPF-driven inference).

## Extending the list

### Per-invocation

```bash
mailsec-probe --dkim-selector my-corp1 --dkim-selector my-corp2 example.com
```

### Replace the embedded list entirely

```bash
mailsec-probe --dkim-selectors-file ./my-selectors.yaml example.com
```

YAML format:

```yaml
selectors:
  - default
  - my-corp1
  - my-corp2
```

User-supplied selectors are de-duplicated against the base list.

## Phase 1.5: SPF-driven inference

The planned enhancement parses the SPF record at the apex and adds
selectors implied by recognised includes:

| SPF token observed | Selectors to add |
|--------------------|------------------|
| `include:_spf.google.com` | `google`, plus recent Google date-style selectors |
| `include:spf.protection.outlook.com` | `selector1-<tenantid>`, `selector2-<tenantid>` |
| `include:amazonses.com` | `<key>-<region>._domainkey` patterns (limited; per-tenant) |
| `include:spf.messagingengine.com` (Fastmail) | `fm1`, `fm2`, `fm3` (already in default list) |
| `include:mailgun.org` | `mg`, `mta`, `krs` |

The exact mapping table will live alongside the existing YAML and be
documented here when Phase 1.5 lands.

## What we deliberately don't do

- **Brute-force selector enumeration**: there is no practical way to
  iterate all possible names. Even ASCII-only and length-bounded the
  space is enormous and probing it would be hostile.
- **Reading authoritative NS for hints**: NS responses do not enumerate
  child names.
- **DNS zone transfers (AXFR/IXFR)**: refused by every well-run
  authoritative server and would be invasive even when permitted.
- **Reading received-mail headers**: works perfectly but moves the
  tool out of "non-invasive observer" territory.
