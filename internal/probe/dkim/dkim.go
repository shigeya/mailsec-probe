// Package dkim observes DKIM TXT records at <selector>._domainkey.<domain>
// across a configured set of selectors.
package dkim

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	"golang.org/x/sync/errgroup"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
	"github.com/shigeya/mailsec-probe/rules"
)

const name = "dkim"

// defaultConcurrency caps parallel selector lookups per domain.
const defaultConcurrency = 8

// Probe observes DKIM with a fixed selector set.
type Probe struct {
	DNS         dnsclient.Client
	Selectors   []string
	Concurrency int
	IncludeRaw  bool
}

// LoadSelectors parses a YAML document of the form:
//
//	selectors:
//	  - default
//	  - google
//
// data may be nil to use the embedded default list.
func LoadSelectors(data []byte) ([]string, error) {
	if len(data) == 0 {
		data = rules.DKIMSelectorsYAML
	}
	var doc struct {
		Selectors []string `yaml:"selectors"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse dkim selectors yaml: %w", err)
	}
	return doc.Selectors, nil
}

// New constructs a Probe. If selectors is empty the embedded default
// list is loaded. extras are appended de-duplicated after the base set.
func New(d dnsclient.Client, extras []string, includeRaw bool) (*Probe, error) {
	base, err := LoadSelectors(nil)
	if err != nil {
		return nil, err
	}
	merged := dedupe(append(base, extras...))
	return &Probe{
		DNS:         d,
		Selectors:   merged,
		Concurrency: defaultConcurrency,
		IncludeRaw:  includeRaw,
	}, nil
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Key is one observed DKIM key.
type Key struct {
	Selector  string `json:"selector"`
	KeyType   string `json:"key_type,omitempty"` // rsa / ed25519 (k=)
	KeySize   int    `json:"key_size,omitempty"` // bits (rsa)
	Flags     string `json:"flags,omitempty"`    // t=
	Service   string `json:"service,omitempty"`  // s=
	Revoked   bool   `json:"revoked,omitempty"`  // empty p= => revoked
	PublicKey string `json:"public_key,omitempty"`
	Raw       string `json:"raw,omitempty"`
}

// Details is the structured DKIM detail payload.
type Details struct {
	SelectorsTried []string `json:"selectors_tried"`
	SelectorsFound []string `json:"selectors_found,omitempty"`
	Keys           []Key    `json:"keys,omitempty"`
}

// Summary returns a short human description (used by the human formatter).
func (d Details) Summary() string {
	if len(d.SelectorsFound) == 0 {
		return fmt.Sprintf("0/%d selectors", len(d.SelectorsTried))
	}
	// Show selectors with key size for the first one if we have it.
	tag := strings.Join(d.SelectorsFound, ", ")
	if len(d.Keys) > 0 {
		k := d.Keys[0]
		if k.KeySize > 0 {
			return fmt.Sprintf("%s (%s %d-bit)", tag, k.KeyType, k.KeySize)
		}
		if k.KeyType != "" {
			return fmt.Sprintf("%s (%s)", tag, k.KeyType)
		}
	}
	return tag
}

// Run probes every configured selector and returns a Feature.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	conc := p.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}

	type result struct {
		selector string
		raw      string
		pairs    []txttag.Pair
		sig      signals.Signal
		hit      bool
	}
	results := make([]result, len(p.Selectors))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(conc)
	for i, sel := range p.Selectors {
		g.Go(func() error {
			target := sel + "._domainkey." + domain
			res, err := p.DNS.LookupTXT(gctx, target)
			r := result{
				selector: sel,
				sig: signals.Signal{
					Source: signals.SourceDNSTxt,
					Target: target,
					OK:     err == nil,
				},
			}
			if err != nil {
				r.sig.Err = err.Error()
				results[i] = r
				return nil
			}
			r.sig.Records = res.Records
			if raw, pairs, ok := txttag.PickByVersion(res.Records, "DKIM1"); ok {
				r.raw = raw
				r.pairs = pairs
				r.hit = true
			} else if len(res.Records) > 0 {
				// Some operators omit v=DKIM1. Treat any TXT with p= or k= as a
				// likely DKIM key with reduced confidence.
				for _, rec := range res.Records {
					ps := txttag.Parse(rec)
					if txttag.Has(ps, "p") || txttag.Has(ps, "k") {
						r.raw = rec
						r.pairs = ps
						r.hit = true
						break
					}
				}
			}
			results[i] = r
			return nil
		})
	}
	_ = g.Wait()

	var (
		mu       sync.Mutex
		sigs     []signals.Signal
		tried    []string
		found    []string
		keys     []Key
		anyFatal bool
	)
	for _, r := range results {
		tried = append(tried, r.selector)
		mu.Lock()
		sigs = append(sigs, r.sig)
		mu.Unlock()
		if !r.sig.OK {
			anyFatal = true // network-level failure
			continue
		}
		if r.hit {
			found = append(found, r.selector)
			keys = append(keys, parseKey(r.selector, r.raw, r.pairs, p.IncludeRaw))
		}
	}

	sort.Strings(found)

	d := Details{
		SelectorsTried: tried,
		SelectorsFound: found,
		Keys:           keys,
	}

	// Count "live" vs "revoked" hits. A key with v=DKIM1 and an empty
	// p= tag is an explicit revocation (RFC 6376 §3.6.1). Some
	// operators publish such a record as a wildcard, which would
	// otherwise look like "every selector is configured" — we treat
	// those as ABSENT instead.
	liveKeys := 0
	for _, k := range keys {
		if !k.Revoked {
			liveKeys++
		}
	}

	switch {
	case liveKeys > 0:
		liveSel := make([]string, 0, liveKeys)
		for _, k := range keys {
			if !k.Revoked {
				liveSel = append(liveSel, k.Selector)
			}
		}
		sort.Strings(liveSel)
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusPresent,
			Confidence: 0.95,
			Reasons:    []string{fmt.Sprintf("DKIM key(s) at: %s", strings.Join(liveSel, ", "))},
			Details:    d,
			Signals:    sigs,
		}
	case len(found) > 0 && liveKeys == 0:
		// Every found record was a revocation. Distinguish a likely
		// wildcard ("everything revoked, same record everywhere") from
		// a targeted single-selector revocation.
		reason := "all matched selectors return revoked DKIM keys (likely wildcard TXT)"
		if len(found) <= 2 {
			reason = "matched selector(s) return revoked DKIM keys (empty p=)"
		}
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.9,
			Reasons:    []string{reason},
			Details:    d,
			Signals:    sigs,
		}
	case anyFatal && len(found) == 0:
		// We had network errors; can't say absent with confidence.
		// If at least most lookups succeeded we still report absent.
		successCount := 0
		for _, r := range results {
			if r.sig.OK {
				successCount++
			}
		}
		if successCount < len(results)/2 {
			return signals.Feature{
				Name:       name,
				Status:     signals.StatusUnknown,
				Confidence: 0.2,
				Reasons:    []string{"too many selector lookups failed"},
				Details:    d,
				Signals:    sigs,
			}
		}
		fallthrough
	default:
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.5,
			Reasons: []string{
				fmt.Sprintf("no DKIM key at any of %d known selectors", len(tried)),
				"absence is heuristic — domain may use an unknown selector",
			},
			Details: d,
			Signals: sigs,
		}
	}
}

func parseKey(selector, raw string, pairs []txttag.Pair, includeRaw bool) Key {
	k := Key{Selector: selector, KeyType: "rsa"} // k=rsa is the default per RFC
	if v := txttag.Get(pairs, "k"); v != "" {
		k.KeyType = v
	}
	if v := txttag.Get(pairs, "t"); v != "" {
		k.Flags = v
	}
	if v := txttag.Get(pairs, "s"); v != "" {
		k.Service = v
	}
	p := txttag.Get(pairs, "p")
	if p == "" {
		k.Revoked = true
	} else {
		// Strip whitespace some operators inject into long base64 strings.
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, p)
		k.PublicKey = clean
		if k.KeyType == "rsa" {
			if size := rsaKeySize(clean); size > 0 {
				k.KeySize = size
			}
		}
	}
	if includeRaw {
		k.Raw = raw
	}
	return k
}

// rsaKeySize returns the modulus size in bits for an RSA SubjectPublicKeyInfo
// encoded in base64. Returns 0 on parse failure.
//
// We avoid pulling crypto/x509 just for this: DKIM RSA keys are stored as
// SubjectPublicKeyInfo (RFC 6376 §3.6.1), and the modulus size correlates
// closely with the encoded length. Heuristic mapping:
//
//	~ 218 chars  -> 1024
//	~ 392 chars  -> 2048
//	~ 736 chars  -> 4096
//
// For exact values we decode the DER and walk to the modulus INTEGER.
func rsaKeySize(b64 string) int {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0
	}
	bits := parseRSAModulusBits(der)
	if bits > 0 {
		return bits
	}
	// Heuristic fallback based on encoded length.
	switch n := len(b64); {
	case n > 700:
		return 4096
	case n > 380:
		return 2048
	case n > 200:
		return 1024
	}
	return 0
}

// parseRSAModulusBits parses a minimal subset of the DER SubjectPublicKeyInfo
// (or bare RSAPublicKey) to extract the modulus length. Returns 0 on any
// parse mismatch — callers should fall back to a heuristic.
func parseRSAModulusBits(der []byte) int {
	// We walk just enough to find the first INTEGER whose length matches
	// a plausible RSA modulus (>= 64 bytes / 512 bits).
	for i := 0; i < len(der); i++ {
		if der[i] != 0x02 { // INTEGER tag
			continue
		}
		if i+1 >= len(der) {
			return 0
		}
		l := int(der[i+1])
		off := i + 2
		if l&0x80 != 0 {
			numBytes := l & 0x7f
			if numBytes == 0 || off+numBytes > len(der) {
				continue
			}
			l = 0
			for j := 0; j < numBytes; j++ {
				l = l<<8 | int(der[off+j])
			}
			off += numBytes
		}
		if l < 64 || off+l > len(der) {
			continue
		}
		// Skip leading zero byte (sign bit padding) if present.
		bytes := l
		if der[off] == 0x00 {
			bytes--
		}
		return bytes * 8
	}
	return 0
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
