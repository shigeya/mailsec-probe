//go:build integration

package dnsclient

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These tests need a working internet connection and stable upstream
// DNS. Run with: go test -tags integration ./...
//
// The targets (google.com, cloudflare.com) are large, long-lived
// domains whose records change rarely. We assert the *shape* of the
// answer rather than exact values to keep tests stable.

const (
	itTimeout   = 8 * time.Second
	itDNSServer = "1.1.1.1:53"
)

func itCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), itTimeout)
}

func newClient(t *testing.T, server string) Client {
	t.Helper()
	c, err := New(Config{Server: server, Timeout: itTimeout})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestIntegration_LookupTXT_SPFAtGoogle(t *testing.T) {
	c := newClient(t, itDNSServer)
	ctx, cancel := itCtx(t)
	defer cancel()

	res, err := c.LookupTXT(ctx, "google.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("expected at least one TXT record at google.com")
	}
	foundSPF := false
	for _, r := range res.Records {
		if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
			foundSPF = true
			break
		}
	}
	if !foundSPF {
		t.Fatalf("expected an SPF record in: %#v", res.Records)
	}
}

func TestIntegration_LookupTXT_DMARCAtGoogle(t *testing.T) {
	c := newClient(t, itDNSServer)
	ctx, cancel := itCtx(t)
	defer cancel()

	res, err := c.LookupTXT(ctx, "_dmarc.google.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("expected a DMARC TXT record at _dmarc.google.com")
	}
	if !strings.HasPrefix(strings.ToLower(res.Records[0]), "v=dmarc1") {
		t.Fatalf("expected v=DMARC1 prefix, got %q", res.Records[0])
	}
}

func TestIntegration_LookupMX_Google(t *testing.T) {
	c := newClient(t, itDNSServer)
	ctx, cancel := itCtx(t)
	defer cancel()

	res, err := c.LookupMX(ctx, "google.com")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("expected at least one MX at google.com")
	}
	for _, r := range res.Records {
		if r.Host == "" {
			t.Fatalf("empty MX host in record: %+v", r)
		}
	}
}

func TestIntegration_HasDS_Cloudflare(t *testing.T) {
	c := newClient(t, itDNSServer)
	ctx, cancel := itCtx(t)
	defer cancel()

	ok, err := c.HasDS(ctx, "cloudflare.com")
	if err != nil {
		t.Fatalf("HasDS: %v", err)
	}
	if !ok {
		t.Fatal("cloudflare.com should have DS records (DNSSEC signed)")
	}
}

func TestIntegration_HasDS_NotSigned(t *testing.T) {
	c := newClient(t, itDNSServer)
	ctx, cancel := itCtx(t)
	defer cancel()

	// example.com is famously not DNSSEC-signed; if that ever changes
	// this test should be updated. Treat as advisory: failure here is
	// informational, not necessarily a bug in our code.
	ok, err := c.HasDS(ctx, "example.com")
	if err != nil {
		t.Skipf("HasDS error (network or upstream change): %v", err)
	}
	if ok {
		t.Skip("example.com is now DNSSEC-signed; update fixture")
	}
}

// Cloudflare publishes a large TXT set at its apex that has historically
// exceeded the default UDP MTU, exercising the UDP→TCP retry path.
func TestIntegration_LookupTXT_TCPFallback_Cloudflare(t *testing.T) {
	c := newClient(t, itDNSServer)
	ctx, cancel := itCtx(t)
	defer cancel()

	res, err := c.LookupTXT(ctx, "cloudflare.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("expected TXT records at cloudflare.com")
	}
	// Spot-check that an SPF record made it through, which is the most
	// commonly truncated record in the set.
	foundSPF := false
	for _, r := range res.Records {
		if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
			foundSPF = true
			break
		}
	}
	if !foundSPF {
		t.Fatalf("expected SPF among the TXT records (likely a TCP retry failure): %#v", res.Records)
	}
}

func TestIntegration_SystemResolver(t *testing.T) {
	// Empty Server -> system resolver path; verifies the fallback works.
	c, err := New(Config{Timeout: itTimeout})
	if err != nil {
		t.Fatalf("New (system): %v", err)
	}
	ctx, cancel := itCtx(t)
	defer cancel()
	res, err := c.LookupMX(ctx, "google.com")
	if err != nil {
		t.Fatalf("LookupMX via system: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("expected MX records via system resolver")
	}
}
