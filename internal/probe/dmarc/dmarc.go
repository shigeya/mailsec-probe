// Package dmarc observes the DMARC TXT record at _dmarc.<domain>.
package dmarc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/httpfetcher"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const name = "dmarc"

// Probe observes DMARC.
type Probe struct {
	DNS              dnsclient.Client
	HTTP             httpfetcher.Fetcher // optional; nil disables rua reachability
	EnableRUACheck   bool                // perform HEAD against https:// rua endpoints
	IncludeRaw       bool
}

// New constructs a Probe. RUA reachability checking is enabled by
// default and uses a fresh HTTPS fetcher with a short timeout.
func New(d dnsclient.Client, includeRaw bool) *Probe {
	return &Probe{
		DNS:            d,
		HTTP:           httpfetcher.New(5*time.Second, ""),
		EnableRUACheck: true,
		IncludeRaw:     includeRaw,
	}
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Details is the structured DMARC detail payload.
type Details struct {
	Policy           string         `json:"policy,omitempty"`            // p=
	SubdomainPolicy  string         `json:"subdomain_policy,omitempty"`  // sp=
	Percent          string         `json:"percent,omitempty"`           // pct=
	AggregateReports string         `json:"aggregate_reports,omitempty"` // rua=
	FailureReports   string         `json:"failure_reports,omitempty"`   // ruf=
	ASPF             string         `json:"aspf,omitempty"`              // aspf= (strict/relaxed)
	ADKIM            string         `json:"adkim,omitempty"`             // adkim=
	RUAEndpoints     []RUAEndpoint  `json:"rua_endpoints,omitempty"`     // per-URI reachability
	Raw              string         `json:"raw,omitempty"`
}

// RUAEndpoint is one parsed rua= URI plus reachability data when known.
type RUAEndpoint struct {
	URI       string `json:"uri"`
	Scheme    string `json:"scheme"` // mailto | https | other
	Checked   bool   `json:"checked"`
	Reachable bool   `json:"reachable,omitempty"`
	Status    int    `json:"http_status,omitempty"`
	Err       string `json:"err,omitempty"`
}

// Summary returns a short human description (used by the human formatter).
func (d Details) Summary() string {
	parts := []string{fmt.Sprintf("p=%s", emptyAs(d.Policy, "?"))}
	if d.SubdomainPolicy != "" && d.SubdomainPolicy != d.Policy {
		parts = append(parts, "sp="+d.SubdomainPolicy)
	}
	if d.Percent != "" && d.Percent != "100" {
		parts = append(parts, "pct="+d.Percent)
	}
	if d.AggregateReports != "" {
		ruaTag := "rua"
		if checked, reachable := summarizeRUA(d.RUAEndpoints); checked {
			if reachable {
				ruaTag = "rua✓"
			} else {
				ruaTag = "rua✗"
			}
		}
		parts = append(parts, ruaTag)
	}
	return strings.Join(parts, ", ")
}

// summarizeRUA returns (anyChecked, allReachable).
func summarizeRUA(eps []RUAEndpoint) (bool, bool) {
	anyChecked := false
	allReachable := true
	for _, e := range eps {
		if !e.Checked {
			continue
		}
		anyChecked = true
		if !e.Reachable {
			allReachable = false
		}
	}
	return anyChecked, allReachable
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

	// rua= reachability: parse the URI list and HEAD any https endpoints.
	if d.AggregateReports != "" {
		d.RUAEndpoints = checkRUAReachability(ctx, d.AggregateReports, p.HTTP, p.EnableRUACheck)
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

// checkRUAReachability parses the rua= value (comma-separated URI list
// per RFC 7489 §6.3) and performs a HEAD against any https URI when
// fetcher is non-nil and enabled is true. mailto: endpoints are
// recorded but never probed (we are non-invasive by design).
func checkRUAReachability(ctx context.Context, ruaValue string, fetcher httpfetcher.Fetcher, enabled bool) []RUAEndpoint {
	out := []RUAEndpoint{}
	for _, raw := range strings.Split(ruaValue, ",") {
		uri := strings.TrimSpace(raw)
		if uri == "" {
			continue
		}
		ep := RUAEndpoint{URI: uri, Scheme: schemeOf(uri)}
		if enabled && fetcher != nil && ep.Scheme == "https" {
			status, err := fetcher.Head(ctx, uri)
			ep.Checked = true
			ep.Status = status
			if err != nil {
				ep.Err = err.Error()
				ep.Reachable = false
			} else {
				// Any 2xx or 3xx is considered reachable; many DMARC report
				// receivers respond with redirects to their auth flow.
				ep.Reachable = status >= 200 && status < 400
			}
		}
		out = append(out, ep)
	}
	return out
}

func schemeOf(uri string) string {
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		return "mailto"
	case strings.HasPrefix(lower, "https:"):
		return "https"
	case strings.HasPrefix(lower, "http:"):
		return "http"
	default:
		return "other"
	}
}

