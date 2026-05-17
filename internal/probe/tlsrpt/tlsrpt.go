// Package tlsrpt observes the TLS-RPT TXT record at _smtp._tls.<domain>.
//
// Reference: RFC 8460. The record advertises a reporting endpoint for
// failed SMTP TLS negotiations.
package tlsrpt

import (
	"context"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "tls-rpt"

// Probe observes TLS-RPT.
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

// Details is the structured TLS-RPT detail payload.
type Details struct {
	ReportingURIs string `json:"rua,omitempty"`
	Raw           string `json:"raw,omitempty"`
}

// Summary returns a short human description (used by the human formatter).
func (d Details) Summary() string {
	if d.ReportingURIs == "" {
		return ""
	}
	return "rua=" + d.ReportingURIs
}

// Run observes TLS-RPT and returns a Feature.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	target := "_smtp._tls." + domain
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
			Reasons:    []string{"TLS-RPT TXT lookup failed: " + err.Error()},
			Signals:    []signals.Signal{sig},
		}
	}
	sig.Records = res.Records

	raw, pairs, ok := txttag.PickByVersion(res.Records, "TLSRPTv1")
	if !ok {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.9,
			Reasons:    []string{"no v=TLSRPTv1 TXT at " + target},
			Signals:    []signals.Signal{sig},
		}
	}

	d := Details{
		ReportingURIs: txttag.Get(pairs, "rua"),
	}
	if p.IncludeRaw {
		d.Raw = raw
	}

	status := signals.StatusPresent
	reasons := []string{"v=TLSRPTv1"}
	if d.ReportingURIs == "" {
		status = signals.StatusMisconfigured
		reasons = append(reasons, "TLS-RPT record lacks required rua= tag")
	}

	return signals.Feature{
		Name:       name,
		Status:     status,
		Confidence: 0.9,
		Reasons:    reasons,
		Details:    d,
		Signals:    []signals.Signal{sig},
	}
}
