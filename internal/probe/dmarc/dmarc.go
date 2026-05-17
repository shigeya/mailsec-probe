// Package dmarc observes the DMARC TXT record at _dmarc.<domain>.
package dmarc

import (
	"context"
	"fmt"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "dmarc"

// Probe observes DMARC.
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

// Details is the structured DMARC detail payload.
type Details struct {
	Policy           string `json:"policy,omitempty"`            // p=
	SubdomainPolicy  string `json:"subdomain_policy,omitempty"`  // sp=
	Percent          string `json:"percent,omitempty"`           // pct=
	AggregateReports string `json:"aggregate_reports,omitempty"` // rua=
	FailureReports   string `json:"failure_reports,omitempty"`   // ruf=
	ASPF             string `json:"aspf,omitempty"`              // aspf= (strict/relaxed)
	ADKIM            string `json:"adkim,omitempty"`             // adkim=
	Raw              string `json:"raw,omitempty"`
}

// Run observes DMARC and returns a Feature.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	target := "_dmarc." + domain
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
			Reasons:    []string{"DMARC TXT lookup failed: " + err.Error()},
			Signals:    []signals.Signal{sig},
		}
	}
	sig.Records = res.Records

	raw, pairs, ok := txttag.PickByVersion(res.Records, "DMARC1")
	if !ok {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.9,
			Reasons:    []string{"no v=DMARC1 TXT at " + target},
			Signals:    []signals.Signal{sig},
		}
	}

	d := Details{
		Policy:           txttag.Get(pairs, "p"),
		SubdomainPolicy:  txttag.Get(pairs, "sp"),
		Percent:          txttag.Get(pairs, "pct"),
		AggregateReports: txttag.Get(pairs, "rua"),
		FailureReports:   txttag.Get(pairs, "ruf"),
		ASPF:             txttag.Get(pairs, "aspf"),
		ADKIM:            txttag.Get(pairs, "adkim"),
	}
	if p.IncludeRaw {
		d.Raw = raw
	}

	status := signals.StatusPresent
	reasons := []string{fmt.Sprintf("p=%s", emptyAs(d.Policy, "(missing)"))}
	switch d.Policy {
	case "":
		status = signals.StatusMisconfigured
		reasons = append(reasons, "DMARC record lacks required p= tag")
	case "none":
		reasons = append(reasons, "monitor-only (no enforcement)")
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

func emptyAs(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
