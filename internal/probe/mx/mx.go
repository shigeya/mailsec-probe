// Package mx observes the MX records of a domain.
package mx

import (
	"context"
	"fmt"
	"sort"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "mx"

// Probe observes MX records.
type Probe struct {
	DNS dnsclient.Client
}

// New constructs a Probe.
func New(d dnsclient.Client) *Probe { return &Probe{DNS: d} }

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Details is the structured detail payload.
type Details struct {
	Hosts []Host `json:"hosts"`
}

// Host is one MX entry.
type Host struct {
	Preference uint16 `json:"preference"`
	Host       string `json:"host"`
}

// Run observes MX records and returns a Feature.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	res, err := p.DNS.LookupMX(ctx, domain)
	sig := signals.Signal{
		Source: signals.SourceDNSMX,
		Target: domain,
		OK:     err == nil,
	}
	if err != nil {
		sig.Err = err.Error()
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusUnknown,
			Confidence: 0,
			Reasons:    []string{"MX lookup failed: " + err.Error()},
			Signals:    []signals.Signal{sig},
		}
	}

	if len(res.Records) == 0 {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 0.95,
			Reasons:    []string{"no MX records"},
			Details:    Details{},
			Signals:    []signals.Signal{sig},
		}
	}

	hosts := make([]Host, 0, len(res.Records))
	for _, r := range res.Records {
		hosts = append(hosts, Host{Preference: r.Preference, Host: r.Host})
		sig.Records = append(sig.Records, fmt.Sprintf("%d %s", r.Preference, r.Host))
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].Preference < hosts[j].Preference })

	return signals.Feature{
		Name:       name,
		Status:     signals.StatusPresent,
		Confidence: 1.0,
		Reasons:    []string{fmt.Sprintf("%d MX record(s)", len(hosts))},
		Details:    Details{Hosts: hosts},
		Signals:    []signals.Signal{sig},
	}
}
