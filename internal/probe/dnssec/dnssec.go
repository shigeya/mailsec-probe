// Package dnssec observes whether the apex zone is DNSSEC-signed.
//
// Phase 1 strategy (per design): rely on the AD (Authenticated Data) bit
// set by a validating recursive resolver, augmented by the presence of
// DS records in the parent zone. We do NOT perform our own DNSKEY/DS
// chain validation in this phase.
package dnssec

import (
	"context"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "dnssec"

// Probe observes DNSSEC indicators.
type Probe struct {
	DNS dnsclient.Client
}

// New constructs a Probe.
func New(d dnsclient.Client) *Probe { return &Probe{DNS: d} }

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Details is the structured DNSSEC detail payload.
type Details struct {
	ADBitOnTXT bool `json:"ad_bit_on_txt"`
	HasDS      bool `json:"has_ds"`
}

// Summary returns a short human description (used by the human formatter).
// Returns empty string when no indicators are present; the formatter then
// falls back to the verdict reason ("no DS in parent and no AD bit ...").
func (d Details) Summary() string {
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
//
// We piggy-back a TXT query on the apex (where SPF lives anyway) to
// observe AD, then query DS at the apex (which lives in the parent
// zone). Either positive indicator is enough to call DNSSEC present;
// AD without DS is unusual but possible mid-rollout.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
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

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
