// Package mtasts observes MTA-STS (RFC 8461):
//
//  1. A TXT record at _mta-sts.<domain> advertises a policy ID.
//  2. The policy itself is fetched over HTTPS from
//     https://mta-sts.<domain>/.well-known/mta-sts.txt
//
// The TXT publishes the policy id and version. The HTTPS body is a
// key/value document (one per line) with mode, mx, and max_age.
package mtasts

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/httpfetcher"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const (
	name        = "mta-sts"
	defaultPath = "/.well-known/mta-sts.txt"
)

// HTTPFetcher is a local alias for httpfetcher.Fetcher to preserve
// MTA-STS test imports.
type HTTPFetcher = httpfetcher.Fetcher

// Probe observes MTA-STS.
type Probe struct {
	DNS        dnsclient.Client
	HTTP       HTTPFetcher
	IncludeRaw bool
}

// New constructs a Probe with a default HTTPS fetcher.
func New(d dnsclient.Client, includeRaw bool) *Probe {
	return &Probe{
		DNS:        d,
		HTTP:       httpfetcher.New(8*time.Second, ""),
		IncludeRaw: includeRaw,
	}
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Policy is the parsed mta-sts.txt body.
type Policy struct {
	Version string   `json:"version,omitempty"`
	Mode    string   `json:"mode,omitempty"` // enforce / testing / none
	MX      []string `json:"mx,omitempty"`
	MaxAge  string   `json:"max_age,omitempty"`
	Raw     string   `json:"raw,omitempty"`
}

// Details is the structured MTA-STS detail payload.
type Details struct {
	DNSRecord struct {
		ID  string `json:"id,omitempty"`
		Raw string `json:"raw,omitempty"`
	} `json:"dns_record"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Policy     Policy    `json:"policy,omitempty"`
	MXMatch    *MXMatch  `json:"mx_match,omitempty"`
}

// MXMatch summarises the per-host comparison of real MX records
// against the patterns advertised in the MTA-STS policy.
type MXMatch struct {
	Checked       bool     `json:"checked"`
	AllMatched    bool     `json:"all_matched"`
	Hosts         []string `json:"hosts,omitempty"`
	Unmatched     []string `json:"unmatched,omitempty"`
	PolicyPatterns []string `json:"policy_patterns,omitempty"`
}

// Summary returns a short human description (used by the human formatter).
func (d Details) Summary() string {
	parts := []string{}
	if d.Policy.Mode != "" {
		parts = append(parts, "mode="+d.Policy.Mode)
	}
	if d.Policy.MaxAge != "" {
		parts = append(parts, "max_age="+d.Policy.MaxAge)
	}
	if len(d.Policy.MX) > 0 {
		parts = append(parts, fmt.Sprintf("%d mx pattern(s)", len(d.Policy.MX)))
	}
	if d.HTTPStatus != 0 && d.HTTPStatus != 200 {
		parts = append(parts, fmt.Sprintf("HTTP %d", d.HTTPStatus))
	}
	return strings.Join(parts, ", ")
}

// Run observes both the DNS marker and the HTTPS policy.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	d := Details{}
	var sigs []signals.Signal
	var reasons []string

	// 1. DNS TXT
	dnsTarget := "_mta-sts." + domain
	dnsRes, dnsErr := p.DNS.LookupTXT(ctx, dnsTarget)
	dnsSig := signals.Signal{Source: signals.SourceDNSTxt, Target: dnsTarget, OK: dnsErr == nil}
	if dnsErr != nil {
		dnsSig.Err = dnsErr.Error()
	} else {
		dnsSig.Records = dnsRes.Records
	}
	sigs = append(sigs, dnsSig)

	var (
		dnsPresent bool
		dnsRaw     string
	)
	if dnsErr == nil {
		if raw, pairs, ok := txttag.PickByVersion(dnsRes.Records, "STSv1"); ok {
			dnsPresent = true
			dnsRaw = raw
			d.DNSRecord.ID = txttag.Get(pairs, "id")
			if p.IncludeRaw {
				d.DNSRecord.Raw = raw
			}
		}
	}
	_ = dnsRaw

	// 2. HTTPS policy
	httpsURL := "https://mta-sts." + domain + defaultPath
	httpsTarget := httpsURL
	status, body, httpErr := p.HTTP.Get(ctx, httpsURL)
	httpSig := signals.Signal{Source: signals.SourceHTTPSGet, Target: httpsTarget, OK: httpErr == nil && status == http.StatusOK}
	if httpErr != nil {
		httpSig.Err = httpErr.Error()
	}
	if status > 0 {
		httpSig.Meta = map[string]string{"status": fmt.Sprintf("%d", status)}
	}
	sigs = append(sigs, httpSig)

	var policyPresent bool
	if httpErr == nil && status == http.StatusOK {
		policy := parsePolicy(body)
		if p.IncludeRaw {
			policy.Raw = body
		}
		d.HTTPStatus = status
		d.Policy = policy
		if policy.Mode != "" || policy.Version != "" {
			policyPresent = true
		}
	} else if status > 0 {
		d.HTTPStatus = status
	}

	// 3. If we have both halves, do the MX-vs-policy consistency check.
	if dnsPresent && policyPresent && len(d.Policy.MX) > 0 {
		mxRes, mxErr := p.DNS.LookupMX(ctx, domain)
		mxSig := signals.Signal{Source: signals.SourceDNSMX, Target: domain, OK: mxErr == nil}
		if mxErr != nil {
			mxSig.Err = mxErr.Error()
		}
		sigs = append(sigs, mxSig)
		if mxErr == nil && len(mxRes.Records) > 0 {
			hosts := make([]string, 0, len(mxRes.Records))
			for _, m := range mxRes.Records {
				hosts = append(hosts, m.Host)
			}
			match := compareMXAgainstPolicy(hosts, d.Policy.MX)
			match.Checked = true
			d.MXMatch = &match
		}
	}

	// 4. Decide overall status.
	switch {
	case dnsPresent && policyPresent:
		mode := d.Policy.Mode
		if mode == "" {
			mode = "(unspecified)"
		}
		reasons = append(reasons, "TXT _mta-sts present", "HTTPS policy present", "mode="+mode)
		st := signals.StatusPresent
		conf := 0.95
		if d.Policy.Mode == "none" {
			st = signals.StatusMisconfigured
			reasons = append(reasons, "policy mode=none (advertised but not enforced)")
		}
		if d.MXMatch != nil && d.MXMatch.Checked && !d.MXMatch.AllMatched {
			st = signals.StatusMisconfigured
			reasons = append(reasons,
				fmt.Sprintf("MX host(s) not covered by policy patterns: %s",
					strings.Join(d.MXMatch.Unmatched, ", ")))
		}
		return signals.Feature{
			Name: name, Status: st, Confidence: conf,
			Reasons: reasons, Details: d, Signals: sigs,
		}
	case dnsPresent && !policyPresent:
		return signals.Feature{
			Name: name, Status: signals.StatusMisconfigured, Confidence: 0.85,
			Reasons: []string{"_mta-sts TXT advertised but HTTPS policy missing"},
			Details: d, Signals: sigs,
		}
	case !dnsPresent && policyPresent:
		return signals.Feature{
			Name: name, Status: signals.StatusMisconfigured, Confidence: 0.6,
			Reasons: []string{"HTTPS policy present but no _mta-sts TXT"},
			Details: d, Signals: sigs,
		}
	default:
		return signals.Feature{
			Name: name, Status: signals.StatusAbsent, Confidence: 0.9,
			Reasons: []string{"no _mta-sts TXT and no HTTPS policy"},
			Details: d, Signals: sigs,
		}
	}
}

// compareMXAgainstPolicy reports whether every host in actualHosts is
// covered by at least one pattern in policyPatterns.
//
// Per RFC 8461 §3.2 a pattern is a single MX hostname or a wildcard of
// the form "*.example.com" which matches exactly one label below the
// suffix. Case is ignored.
func compareMXAgainstPolicy(actualHosts, policyPatterns []string) MXMatch {
	m := MXMatch{
		Hosts:          append([]string{}, actualHosts...),
		PolicyPatterns: append([]string{}, policyPatterns...),
	}
	if len(actualHosts) == 0 {
		m.AllMatched = true
		return m
	}
	patterns := make([]string, 0, len(policyPatterns))
	for _, p := range policyPatterns {
		patterns = append(patterns, strings.TrimSuffix(strings.ToLower(p), "."))
	}
	m.AllMatched = true
	for _, h := range actualHosts {
		host := strings.TrimSuffix(strings.ToLower(h), ".")
		if !matchAnyPattern(host, patterns) {
			m.Unmatched = append(m.Unmatched, h)
			m.AllMatched = false
		}
	}
	return m
}

func matchAnyPattern(host string, patterns []string) bool {
	for _, p := range patterns {
		if matchPattern(host, p) {
			return true
		}
	}
	return false
}

func matchPattern(host, pattern string) bool {
	// Exact match
	if host == pattern {
		return true
	}
	// Wildcard "*.suffix" matches one label below suffix.
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[2:]
	if !strings.HasSuffix(host, "."+suffix) {
		return false
	}
	prefix := host[:len(host)-len(suffix)-1]
	// Exactly one label: must not contain a dot.
	return prefix != "" && !strings.Contains(prefix, ".")
}

func parsePolicy(body string) Policy {
	p := Policy{}
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = strings.ToLower(value)
		case "max_age":
			p.MaxAge = value
		case "mx":
			p.MX = append(p.MX, value)
		}
	}
	return p
}

// NewHTTPFetcher is kept for backwards-compatible callers; new code
// should call httpfetcher.New directly.
//
// Deprecated: use httpfetcher.New.
func NewHTTPFetcher(timeout time.Duration, ua string) HTTPFetcher {
	return httpfetcher.New(timeout, ua)
}
