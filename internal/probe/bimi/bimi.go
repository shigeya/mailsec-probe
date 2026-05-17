// Package bimi observes the BIMI TXT record at default._bimi.<domain>.
//
// BIMI lets organizations attach a verified brand logo to authenticated
// mail. We only check DNS presence and pull out l= (logo SVG URI) and
// a= (Verified Mark Certificate URI). VMC validation is out of scope
// for Phase 1.
package bimi

import (
	"context"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "bimi"

// Probe observes BIMI.
type Probe struct {
	DNS        dnsclient.Client
	Selector   string // defaults to "default"
	IncludeRaw bool
}

// New constructs a Probe with selector "default".
func New(d dnsclient.Client, includeRaw bool) *Probe {
	return &Probe{DNS: d, Selector: "default", IncludeRaw: includeRaw}
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Details is the structured BIMI detail payload.
type Details struct {
	LogoURI string `json:"logo_uri,omitempty"` // l=
	VMCURI  string `json:"vmc_uri,omitempty"`  // a=
	Raw     string `json:"raw,omitempty"`
}

// Run observes BIMI and returns a Feature.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	selector := p.Selector
	if selector == "" {
		selector = "default"
	}
	target := selector + "._bimi." + domain
	res, err := p.DNS.LookupTXT(ctx, target)
	sig := signals.Signal{
		Source: signals.SourceDNSTxt,
		Target: target,
		OK:     err == nil,
	}
	if err != nil {
		sig.Err = err.Error()
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusUnknown,
			Confidence: 0,
			Reasons:    []string{"BIMI TXT lookup failed: " + err.Error()},
			Signals:    []signals.Signal{sig},
		}
	}
	sig.Records = res.Records

	raw, pairs, ok := txttag.PickByVersion(res.Records, "BIMI1")
	if !ok {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.85,
			Reasons:    []string{"no v=BIMI1 TXT at " + target},
			Signals:    []signals.Signal{sig},
		}
	}

	d := Details{
		LogoURI: txttag.Get(pairs, "l"),
		VMCURI:  txttag.Get(pairs, "a"),
	}
	if p.IncludeRaw {
		d.Raw = raw
	}

	return signals.Feature{
		Name:       name,
		Status:     signals.StatusPresent,
		Confidence: 0.9,
		Reasons:    []string{"v=BIMI1"},
		Details:    d,
		Signals:    []signals.Signal{sig},
	}
}
