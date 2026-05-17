//go:build integration

package mtasts

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Targets a few large mail providers known to publish MTA-STS policies.
// If a target ever stops publishing, the test will fail loudly and the
// fixture should be updated, but the providers below are conservative.

func TestIntegration_HTTPFetcher_GoogleMTASTS(t *testing.T) {
	h := NewHTTPFetcher(8*time.Second, "mailsec-probe/integration-test")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, body, err := h.Get(ctx, "https://mta-sts.google.com/.well-known/mta-sts.txt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(strings.ToLower(body), "version: stsv1") {
		t.Fatalf("body missing 'version: STSv1': %q", body)
	}
	if !strings.Contains(strings.ToLower(body), "mode:") {
		t.Fatalf("body missing 'mode:': %q", body)
	}
}

func TestIntegration_HTTPFetcher_NonExistent(t *testing.T) {
	h := NewHTTPFetcher(8*time.Second, "mailsec-probe/integration-test")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// example.com famously does NOT publish an MTA-STS policy.
	// We expect either a connection error or a non-200 status.
	status, _, err := h.Get(ctx, "https://mta-sts.example.com/.well-known/mta-sts.txt")
	if err == nil && status == http.StatusOK {
		t.Skip("example.com now publishes an MTA-STS policy; update fixture")
	}
	// Either err != nil (DNS failure / refused) or status >= 400 is fine.
}
