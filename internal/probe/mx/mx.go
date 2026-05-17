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

// Summary returns a short human description (used by the human formatter).
func (d Details) Summary() string {
	if len(d.Hosts) == 0 {
		return "no MX"
	}
	switch len(d.Hosts) {
	case 1:
		return fmt.Sprintf("%d %s", d.Hosts[0].Preference, d.Hosts[0].Host)
	case 2:
		return fmt.Sprintf("%d %s, %d %s",
			d.Hosts[0].Preference, d.Hosts[0].Host,
			d.Hosts[1].Preference, d.Hosts[1].Host)
	default:
		return fmt.Sprintf("%d %s, %d %s, +%d more",
			d.Hosts[0].Preference, d.Hosts[0].Host,
			d.Hosts[1].Preference, d.Hosts[1].Host,
			len(d.Hosts)-2)
	}
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

	// RFC 7505: a single MX record of "0 ." advertises that the domain
	// does not accept mail. Report this as absent with a clear reason.
	if isNullMX(hosts) {
		return signals.Feature{
			Name:       name,
			Status:     signals.StatusAbsent,
			Confidence: 1.0,
			Reasons:    []string{"null MX (RFC 7505): domain explicitly refuses mail"},
			Details:    Details{Hosts: hosts},
			Signals:    []signals.Signal{sig},
		}
	}

	return signals.Feature{
		Name:       name,
		Status:     signals.StatusPresent,
		Confidence: 1.0,
		Reasons:    []string{fmt.Sprintf("%d MX record(s)", len(hosts))},
		Details:    Details{Hosts: hosts},
		Signals:    []signals.Signal{sig},
	}
}

// isNullMX reports whether hosts is exactly the RFC 7505 null MX form.
func isNullMX(hosts []Host) bool {
	if len(hosts) != 1 {
		return false
	}
	h := hosts[0]
	return h.Preference == 0 && (h.Host == "" || h.Host == ".")
}
