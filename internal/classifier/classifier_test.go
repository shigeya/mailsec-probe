package classifier_test

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
)

var updateGolden = flag.Bool("update-golden", false, "rewrite golden files from current output")

// stubHTTP returns the configured policy for any URL.
type stubHTTP struct {
	status int
	body   string
}

func (s stubHTTP) Get(_ context.Context, _ string) (int, string, error) {
	return s.status, s.body, nil
}

// fullyConfigured wires every probe against a Mock DNS that simulates a
// domain with all eight features in place.
func TestRunner_FullyConfiguredGolden(t *testing.T) {
	m := dnsclient.NewMock()

	// SPF at apex
	m.TXT["example.test"] = dnsclient.TXTResult{
		Records: []string{
			"v=spf1 include:_spf.example.test -all",
			"google-site-verification=abc",
		},
		AD: true,
	}

	// DMARC
	m.TXT["_dmarc.example.test"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@example.test; pct=100"},
	}

	// DKIM
	m.TXT["selector1._domainkey.example.test"] = dnsclient.TXTResult{
		Records: []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfake"},
	}

	// MX
	m.MX["example.test"] = dnsclient.MXResult{
		Records: []dnsclient.MX{
			{Host: "mx1.example.test", Preference: 10},
			{Host: "mx2.example.test", Preference: 20},
		},
	}

	// MTA-STS (DNS half)
	m.TXT["_mta-sts.example.test"] = dnsclient.TXTResult{
		Records: []string{"v=STSv1; id=20240101000000Z"},
	}

	// TLS-RPT
	m.TXT["_smtp._tls.example.test"] = dnsclient.TXTResult{
		Records: []string{"v=TLSRPTv1; rua=mailto:tlsrpt@example.test"},
	}

	// BIMI
	m.TXT["default._bimi.example.test"] = dnsclient.TXTResult{
		Records: []string{"v=BIMI1; l=https://example.test/logo.svg"},
	}

	// DNSSEC
	m.DS["example.test"] = true

	// MTA-STS HTTPS half
	httpStub := stubHTTP{
		status: http.StatusOK,
		body: "version: STSv1\nmode: enforce\nmx: mx1.example.test\nmx: mx2.example.test\nmax_age: 604800\n",
	}

	dkimProbe, err := dkim.New(m, nil, false)
	if err != nil {
		t.Fatalf("dkim.New: %v", err)
	}
	dkimProbe.Selectors = []string{"selector1"} // narrow the probe for deterministic output

	mtaProbe := mtasts.New(m, false)
	mtaProbe.HTTP = httpStub

	runner := classifier.New(
		spf.New(m, false),
		dmarc.New(m, false),
		dkimProbe,
		mx.New(m),
		mtaProbe,
		tlsrpt.New(m, false),
		bimi.New(m, false),
		dnssec.New(m),
	)

	rep := runner.Run(context.Background(), "example.test")
	rep.QueriedAt = rep.QueriedAt.Truncate(0) // zero monotonic clock bits
	// Stamp time as zero for golden stability.
	rep.QueriedAt = rep.QueriedAt.UTC()
	for i := range rep.Features {
		// Strip per-signal noise that can vary (Meta map ordering).
		rep.Features[i].Signals = nil
	}
	type stableReport struct {
		Domain   string `json:"domain"`
		Features any    `json:"features"`
	}
	got, err := json.MarshalIndent(stableReport{
		Domain:   rep.Domain,
		Features: rep.Features,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	goldenPath := filepath.Join("testdata", "fully_configured.golden.json")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(goldenPath, append(got, '\n'), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("updated %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (%s): %v\nrun: go test ./internal/classifier -update-golden", goldenPath, err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("golden mismatch.\nWANT:\n%s\nGOT:\n%s", want, got)
	}
}
