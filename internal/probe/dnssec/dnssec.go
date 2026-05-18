// Package dnssec observes whether the apex zone is DNSSEC-signed.
//
// Two modes are supported:
//
//   - "ad-only" (legacy) — rely on the AD (Authenticated Data) bit set
//     by a validating recursive resolver, augmented by the presence of
//     DS records in the parent zone. No own chain validation. Cheap,
//     but cannot detect BOGUS.
//   - "validate" — perform full chain-of-trust validation via
//     [github.com/shigeya/dnsdata-go/verifier]. Distinguishes BOGUS
//     from INSECURE and surfaces the failure point.
package dnssec

import (
	"context"
	"fmt"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "dnssec"

// Mode selects the validation strategy.
type Mode string

const (
	// ModeADOnly relies on the recursive resolver's AD bit plus DS
	// presence. Default for backwards compatibility.
	ModeADOnly Mode = "ad-only"

	// ModeValidate performs chain validation via dnsdata-go.
	ModeValidate Mode = "validate"
)

// Probe observes DNSSEC indicators.
type Probe struct {
	// DNS is the resolver used in ModeADOnly. Always required since
	// the ad-only path falls back to a TXT/DS lookup pair.
	DNS dnsclient.Client

	// Mode selects the validation strategy. Defaults to ModeADOnly
	// when the zero value is used.
	Mode Mode

	// V is the chain validator used in ModeValidate. Ignored in
	// ModeADOnly; required (non-nil) when Mode is ModeValidate.
	V *verifier.Verifier
}

// New constructs a ModeADOnly probe (legacy entry point).
func New(d dnsclient.Client) *Probe { return &Probe{DNS: d, Mode: ModeADOnly} }

// NewWithVerifier constructs a ModeValidate probe.
func NewWithVerifier(d dnsclient.Client, v *verifier.Verifier) *Probe {
	return &Probe{DNS: d, Mode: ModeValidate, V: v}
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Details is the structured DNSSEC detail payload.
//
// In ad-only mode only [ADBitOnTXT] and [HasDS] are populated. In
// validate mode the chain-validation outputs are populated instead;
// the legacy fields remain zero so JSON consumers can detect which
// mode produced the report.
type Details struct {
	// Legacy ad-only fields.
	ADBitOnTXT bool `json:"ad_bit_on_txt,omitempty"`
	HasDS      bool `json:"has_ds,omitempty"`

	// Validate-mode fields.
	Verdict        string `json:"verdict,omitempty"`
	InsecureAt     string `json:"insecure_at,omitempty"`
	InsecureReason string `json:"insecure_reason,omitempty"`
	BogusAt        string `json:"bogus_at,omitempty"`
	BogusReason    string `json:"bogus_reason,omitempty"`
	NegativeReason string `json:"negative_reason,omitempty"`
}

// Summary returns a short human description (used by the human formatter).
// Returns empty string when no indicators are present; the formatter then
// falls back to the verdict reason.
func (d Details) Summary() string {
	if d.Verdict != "" {
		return d.Verdict
	}
	switch {
	case d.HasDS && d.ADBitOnTXT:
		return "DS + AD"
	case d.HasDS:
		return "DS only"
	case d.ADBitOnTXT:
		return "AD only"
	default:
		return ""
	}
}

// Run observes DNSSEC indicators.
func (p *Probe) Run(ctx context.Context, domain string) []signals.Feature {
	return []signals.Feature{p.runOne(ctx, domain)}
}

func (p *Probe) runOne(ctx context.Context, domain string) signals.Feature {
	if p.Mode == ModeValidate {
		return p.runValidate(ctx, domain)
	}
	return p.runADOnly(ctx, domain)
}

// runADOnly retains the Phase 1.0 behaviour: TXT + DS lookups, judging
// from the AD bit and DS presence alone.
func (p *Probe) runADOnly(ctx context.Context, domain string) signals.Feature {
	txt, txtErr := p.DNS.LookupTXT(ctx, domain)
	hasDS, dsErr := p.DNS.HasDS(ctx, domain)

	sigs := []signals.Signal{
		{
			Source: signals.SourceDNSTxt,
			Target: domain,
			OK:     txtErr == nil,
			Meta:   map[string]string{"ad_bit": boolStr(txt.AD)},
		},
		{
			Source: signals.SourceDNSDS,
			Target: domain,
			OK:     dsErr == nil,
			Meta:   map[string]string{"has_ds": boolStr(hasDS)},
		},
	}
	if txtErr != nil {
		sigs[0].Err = txtErr.Error()
	}
	if dsErr != nil {
		sigs[1].Err = dsErr.Error()
	}

	d := Details{
		ADBitOnTXT: txt.AD,
		HasDS:      hasDS,
	}

	if txtErr != nil && dsErr != nil {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusUnknown,
			Confidence: 0,
			Reasons:    []string{"both TXT and DS lookups failed"},
			Details:    d,
			Signals:    sigs,
		}
	}

	switch {
	case d.HasDS && d.ADBitOnTXT:
		return signals.Feature{
			Name: name, Status: signals.StatusPresent, Confidence: 1.0,
			Reasons: []string{"DS present in parent zone", "AD bit set on TXT response"},
			Details: d, Signals: sigs,
		}
	case d.HasDS:
		return signals.Feature{
			Name: name, Status: signals.StatusPresent, Confidence: 0.85,
			Reasons: []string{"DS present in parent zone (AD bit not set; resolver may not validate)"},
			Details: d, Signals: sigs,
		}
	case d.ADBitOnTXT:
		return signals.Feature{
			Name: name, Status: signals.StatusPresent, Confidence: 0.7,
			Reasons: []string{"AD bit set on TXT response (no DS observed)"},
			Details: d, Signals: sigs,
		}
	default:
		return signals.Feature{
			Name: name, Status: signals.StatusAbsent, Confidence: 0.8,
			Reasons: []string{"no DS in parent and no AD bit on TXT"},
			Details: d, Signals: sigs,
		}
	}
}

// runValidate performs chain validation via dnsdata-go.
func (p *Probe) runValidate(ctx context.Context, domain string) signals.Feature {
	if p.V == nil {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusUnknown,
			Confidence: 0,
			Reasons:    []string{"validate mode selected but no Verifier configured"},
			Details:    Details{},
		}
	}

	qname := domain
	if len(qname) == 0 || qname[len(qname)-1] != '.' {
		qname += "."
	}
	r, err := p.V.Validate(ctx, qname, types.TypeTXT)

	sig := signals.Signal{
		Source: signals.SourceDNSTxt,
		Target: domain,
		OK:     err == nil,
		Meta:   map[string]string{"mode": string(ModeValidate)},
	}
	if err != nil {
		sig.Err = err.Error()
	}
	if r != nil {
		sig.Meta["verdict"] = r.Verdict.String()
	}
	sigs := []signals.Signal{sig}

	if err != nil || r == nil {
		errMsg := "validation error"
		if err != nil {
			errMsg = err.Error()
		}
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusUnknown,
			Confidence: 0,
			Reasons:    []string{fmt.Sprintf("chain validation failed: %s", errMsg)},
			Details:    Details{Verdict: "indeterminate"},
			Signals:    sigs,
		}
	}

	d := Details{
		Verdict:        r.Verdict.String(),
		InsecureAt:     r.InsecureAt,
		InsecureReason: r.InsecureReason,
		BogusAt:        r.BogusAt,
		BogusReason:    r.BogusReason,
		NegativeReason: r.NegativeReason,
	}

	switch r.Verdict {
	case verifier.VerdictSecure, verifier.VerdictSecureNoData, verifier.VerdictSecureNXDomain:
		return signals.Feature{
			Name: name, Status: signals.StatusPresent, Confidence: 0.95,
			Reasons: []string{"DNSSEC chain validated from root"},
			Details: d, Signals: sigs,
		}
	case verifier.VerdictInsecure:
		reason := "insecure delegation"
		if r.InsecureAt != "" {
			reason = fmt.Sprintf("insecure delegation at %s", r.InsecureAt)
		}
		if r.InsecureReason != "" {
			reason += " (" + r.InsecureReason + ")"
		}
		return signals.Feature{
			Name: name, Status: signals.StatusAbsent, Confidence: 0.9,
			Reasons: []string{reason},
			Details: d, Signals: sigs,
		}
	case verifier.VerdictBogus:
		reason := "BOGUS"
		if r.BogusAt != "" {
			reason = fmt.Sprintf("BOGUS at %s", r.BogusAt)
		}
		if r.BogusReason != "" {
			reason += ": " + r.BogusReason
		}
		return signals.Feature{
			Name: name, Status: signals.StatusMisconfigured, Confidence: 0.95,
			Reasons: []string{reason},
			Details: d, Signals: sigs,
		}
	default:
		return signals.Feature{
			Name: name, Status: signals.StatusUnknown, Confidence: 0,
			Reasons: []string{"DNSSEC verdict indeterminate"},
			Details: d, Signals: sigs,
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
