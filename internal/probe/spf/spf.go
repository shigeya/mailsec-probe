// Package spf observes the SPF TXT record at the apex.
//
// SPF records (RFC 7208) are space-separated mechanisms, not tag=value.
// The "all" mechanism's qualifier determines enforcement strength:
//
//	-all  fail (strict)
//	~all  softfail (recommended for staged rollout)
//	?all  neutral
//	+all  pass everything (effectively no SPF)
//
// Only one valid SPF record may exist per domain; multiple v=spf1
// records is a misconfiguration.
package spf

import (
	"context"
	"fmt"
	"strings"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "spf"

// Probe observes SPF.
type Probe struct {
	DNS        dnsclient.Client
	IncludeRaw bool
}

// New constructs a Probe.
func New(d dnsclient.Client, includeRaw bool) *Probe {
	return &Probe{DNS: d, IncludeRaw: includeRaw}
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Qualifier names the four SPF "all" qualifiers.
type Qualifier string

const (
	QualifierFail     Qualifier = "fail"     // -all
	QualifierSoftfail Qualifier = "softfail" // ~all
	QualifierNeutral  Qualifier = "neutral"  // ?all
	QualifierPass     Qualifier = "pass"     // +all  (effectively open)
	QualifierMissing  Qualifier = "missing"  // no "all" mechanism
)

// Details is the structured SPF detail payload.
type Details struct {
	Qualifier  Qualifier `json:"qualifier"`
	Includes   []string  `json:"includes,omitempty"`   // include:<domain>
	Redirect   string    `json:"redirect,omitempty"`   // redirect=<domain>
	Mechanisms []string  `json:"mechanisms,omitempty"` // verbatim space-split mechanisms
	Raw        string    `json:"raw,omitempty"`
}

// Summary returns a short human description (used by the human formatter).
func (d Details) Summary() string {
	parts := []string{fmt.Sprintf("qualifier=%s", d.Qualifier)}
	switch {
	case d.Redirect != "":
		parts = append(parts, "redirect="+d.Redirect)
	case len(d.Includes) == 1:
		parts = append(parts, "include="+d.Includes[0])
	case len(d.Includes) > 1:
		parts = append(parts, fmt.Sprintf("%d includes", len(d.Includes)))
	}
	return strings.Join(parts, ", ")
}

// Run observes SPF and returns a Feature.
func (p *Probe) Run(ctx context.Context, domain string) []signals.Feature {
	return []signals.Feature{p.runOne(ctx, domain)}
}

func (p *Probe) runOne(ctx context.Context, domain string) signals.Feature {
	res, err := p.DNS.LookupTXT(ctx, domain)
	sig := signals.Signal{
		Source: signals.SourceDNSTxt,
		Target: domain,
		OK:     err == nil,
	}
	if err != nil {
		sig.Err = err.Error()
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusUnknown,
			Confidence: 0,
			Reasons:    []string{"SPF TXT lookup failed: " + err.Error()},
			Signals:    []signals.Signal{sig},
		}
	}
	sig.Records = res.Records

	spfs := pickSPFRecords(res.Records)
	switch len(spfs) {
	case 0:
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.95,
			Reasons:    []string{"no v=spf1 TXT at apex"},
			Signals:    []signals.Signal{sig},
		}
	case 1:
		// fall through
	default:
		// RFC 7208: multiple SPF records is a PermError.
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusMisconfigured,
			Confidence: 0.95,
			Reasons:    []string{fmt.Sprintf("multiple v=spf1 records (%d) - RFC 7208 PermError", len(spfs))},
			Signals:    []signals.Signal{sig},
		}
	}

	raw := spfs[0]
	d := parseSPF(raw)
	if p.IncludeRaw {
		d.Raw = raw
	}

	reasons := []string{fmt.Sprintf("qualifier=%s", d.Qualifier)}
	status := signals.StatusPresent
	switch d.Qualifier {
	case QualifierPass:
		status = signals.StatusMisconfigured
		reasons = append(reasons, "+all permits any sender (no real protection)")
	case QualifierMissing:
		// "redirect=" delegates the policy to another domain, so the
		// absence of an "all" mechanism is expected and valid (RFC 7208 §6.1).
		if d.Redirect == "" {
			status = signals.StatusMisconfigured
			reasons = append(reasons, "no 'all' mechanism and no redirect modifier")
		} else {
			reasons = append(reasons, "policy delegated via redirect="+d.Redirect)
		}
	}

	return signals.Feature{
		Name:       name,
		Status:     status,
		Confidence: 0.95,
		Reasons:    reasons,
		Details:    d,
		Signals:    []signals.Signal{sig},
	}
}

// pickSPFRecords returns all TXT records whose first token is v=spf1.
func pickSPFRecords(records []string) []string {
	var out []string
	for _, r := range records {
		if isSPF(r) {
			out = append(out, r)
		}
	}
	return out
}

func isSPF(r string) bool {
	t := strings.TrimSpace(r)
	if len(t) < 6 {
		return false
	}
	head := t[:6]
	if !strings.EqualFold(head, "v=spf1") {
		return false
	}
	if len(t) == 6 {
		return true
	}
	// Next char must be whitespace per RFC 7208.
	c := t[6]
	return c == ' ' || c == '\t'
}

func parseSPF(raw string) Details {
	d := Details{Qualifier: QualifierMissing}
	for tok := range strings.FieldsSeq(raw) {
		if strings.EqualFold(tok, "v=spf1") {
			continue
		}
		d.Mechanisms = append(d.Mechanisms, tok)
		lower := strings.ToLower(tok)
		switch {
		case strings.HasPrefix(lower, "include:"):
			d.Includes = append(d.Includes, tok[len("include:"):])
		case strings.HasPrefix(lower, "redirect="):
			d.Redirect = tok[len("redirect="):]
		case lower == "-all":
			d.Qualifier = QualifierFail
		case lower == "~all":
			d.Qualifier = QualifierSoftfail
		case lower == "?all":
			d.Qualifier = QualifierNeutral
		case lower == "+all", lower == "all":
			d.Qualifier = QualifierPass
		}
	}
	return d
}
