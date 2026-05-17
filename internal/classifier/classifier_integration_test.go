//go:build integration

package classifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/shigeya/mailsec-probe/internal/classifier"
	"github.com/shigeya/mailsec-probe/internal/probe/bimi"
	"github.com/shigeya/mailsec-probe/internal/probe/dkim"
	"github.com/shigeya/mailsec-probe/internal/probe/dmarc"
	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/dnssec"
	"github.com/shigeya/mailsec-probe/internal/probe/mtasts"
	"github.com/shigeya/mailsec-probe/internal/probe/mx"
	"github.com/shigeya/mailsec-probe/internal/probe/spf"
	"github.com/shigeya/mailsec-probe/internal/probe/tlsrpt"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

// End-to-end smoke against real DNS and real HTTPS. The assertions are
// intentionally loose: we test that the wiring works and that
// well-known domains return *some* present features. Specific tag
// values change over time and are not asserted here.

func buildAllProbes(t *testing.T) []classifier.Probe {
	t.Helper()
	d, err := dnsclient.New(dnsclient.Config{Server: "1.1.1.1:53", Timeout: 8 * time.Second})
	if err != nil {
		t.Fatalf("dnsclient: %v", err)
	}
	dk, err := dkim.New(d, nil, false)
	if err != nil {
		t.Fatalf("dkim.New: %v", err)
	}
	return []classifier.Probe{
		spf.New(d, false),
		dmarc.New(d, false),
		dk,
		mx.New(d),
		mtasts.New(d, false),
		tlsrpt.New(d, false),
		bimi.New(d, false),
		dnssec.New(d),
	}
}

func runReport(t *testing.T, domain string) signals.Report {
	t.Helper()
	r := classifier.New(buildAllProbes(t)...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.Run(ctx, domain)
}

func featureByName(rep signals.Report, name string) *signals.Feature {
	for i := range rep.Features {
		if rep.Features[i].Name == name {
			return &rep.Features[i]
		}
	}
	return nil
}

func TestIntegration_GoogleHasCoreMailSecurity(t *testing.T) {
	// DKIM is intentionally NOT in the must-present set: Google rotates
	// selectors and old ones (20161025, 20210112) now return revoked
	// records ("v=DKIM1; p="). Our embedded selector list cannot keep
	// up with their rotation cadence — this is a documented limitation
	// of selector-blind DKIM probing.
	rep := runReport(t, "google.com")
	mustPresent := []string{"spf", "dmarc", "mx", "mta-sts", "tls-rpt"}
	for _, name := range mustPresent {
		f := featureByName(rep, name)
		if f == nil {
			t.Errorf("feature %s missing from report", name)
			continue
		}
		if f.Status != signals.StatusPresent {
			t.Errorf("google.com %s = %s (reasons=%v), want present", name, f.Status, f.Reasons)
		}
	}
}

func TestIntegration_CloudflareHasBIMIAndDNSSECAndDKIM(t *testing.T) {
	rep := runReport(t, "cloudflare.com")

	for _, name := range []string{"bimi", "dnssec", "dkim"} {
		f := featureByName(rep, name)
		if f == nil || f.Status != signals.StatusPresent {
			t.Errorf("cloudflare.com %s expected present, got %+v", name, f)
		}
	}
}

// IANA's example.com is a useful real-world fixture: it publishes a
// null MX (RFC 7505) and "v=DKIM1; p=" wildcards at _domainkey, both
// of which used to confuse our parsers. The asserts below pin down
// the corrective behavior in production.
func TestIntegration_ExampleCom_NullMXAndRevokedDKIM(t *testing.T) {
	rep := runReport(t, "example.com")

	mxFeat := featureByName(rep, "mx")
	if mxFeat == nil || mxFeat.Status != signals.StatusAbsent {
		t.Errorf("example.com mx expected absent (null MX), got %+v", mxFeat)
	}

	dkimFeat := featureByName(rep, "dkim")
	if dkimFeat == nil || dkimFeat.Status != signals.StatusAbsent {
		t.Errorf("example.com dkim expected absent (revoked wildcard), got %+v", dkimFeat)
	}

	// Sanity: many features should be absent, none should be unknown.
	for _, f := range rep.Features {
		if f.Status == signals.StatusUnknown {
			t.Errorf("example.com %s came back unknown (likely a probe wiring bug): reasons=%v", f.Name, f.Reasons)
		}
	}
}

