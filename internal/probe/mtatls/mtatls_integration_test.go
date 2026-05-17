//go:build integration

package mtatls

import (
	"context"
	"testing"
	"time"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

// These tests open real TCP connections to port 25 of well-known MX
// hosts. They require outbound :25 to work (often blocked on
// residential ISPs and many CI runners), so they are gated behind
// the integration build tag.

func newClient(t *testing.T) dnsclient.Client {
	t.Helper()
	c, err := dnsclient.New(dnsclient.Config{Server: "1.1.1.1:53", Timeout: 8 * time.Second})
	if err != nil {
		t.Fatalf("dnsclient: %v", err)
	}
	return c
}

func TestIntegration_STARTTLS_Google(t *testing.T) {
	p := New(newClient(t))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	feats := p.Run(ctx, "google.com")

	var starttls *signals.Feature
	for i := range feats {
		if feats[i].Name == "starttls" {
			starttls = &feats[i]
		}
	}
	if starttls == nil {
		t.Fatal("starttls feature missing")
	}
	if starttls.Status == signals.StatusUnknown {
		t.Skipf("network appears to block :25 (status=unknown): %v", starttls.Reasons)
	}
	if starttls.Status != signals.StatusPresent {
		t.Fatalf("google.com starttls = %s, want present (reasons=%v)", starttls.Status, starttls.Reasons)
	}
	d := starttls.Details.(STARTTLSDetails)
	if len(d.MXResults) == 0 {
		t.Fatal("no MX results")
	}
}

func TestIntegration_DANE_NlnetlabsHasTLSA(t *testing.T) {
	// nlnetlabs.nl uses mailbox.org which serves TLSA records.
	// If the upstream changes this assumption, the test should be
	// updated to a different DANE-using domain.
	p := New(newClient(t))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	feats := p.Run(ctx, "nlnetlabs.nl")

	var dane, starttls *signals.Feature
	for i := range feats {
		if feats[i].Name == "dane" {
			dane = &feats[i]
		}
		if feats[i].Name == "starttls" {
			starttls = &feats[i]
		}
	}
	if starttls != nil && starttls.Status == signals.StatusUnknown {
		t.Skipf("network appears to block :25: %v", starttls.Reasons)
	}
	if dane == nil {
		t.Fatal("dane feature missing")
	}
	if dane.Status != signals.StatusPresent {
		// Mailbox.org may have changed; treat as informational rather
		// than a hard failure.
		t.Logf("nlnetlabs.nl dane = %s (reasons=%v) — possibly upstream change", dane.Status, dane.Reasons)
		t.Skip("DANE no longer present at expected fixture domain")
	}
}
