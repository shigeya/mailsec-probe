package dmarc

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestRun_PresentReject(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_dmarc.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"},
	}
	p := New(m, true)
	p.EnableRUACheck = false
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if d.Policy != "reject" {
		t.Fatalf("policy = %s", d.Policy)
	}
	if d.AggregateReports != "mailto:dmarc@example.com" {
		t.Fatalf("rua = %s", d.AggregateReports)
	}
}

func TestRun_Absent(t *testing.T) {
	m := dnsclient.NewMock()
	p := New(m, false)
	p.EnableRUACheck = false
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
}

type stubFetcher struct {
	status int
	err    error
}

func (s stubFetcher) Get(_ context.Context, _ string) (int, string, error) { return s.status, "", s.err }
func (s stubFetcher) Head(_ context.Context, _ string) (int, error)        { return s.status, s.err }

func TestRun_RUAReachable_HTTPS(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_dmarc.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; p=reject; rua=https://reports.example.com/dmarc, mailto:dmarc@example.com"},
	}
	p := New(m, false)
	p.HTTP = stubFetcher{status: 200}
	p.EnableRUACheck = true
	f := p.Run(context.Background(), "example.com")[0]
	d := f.Details.(Details)
	if len(d.RUAEndpoints) != 2 {
		t.Fatalf("rua endpoints = %#v", d.RUAEndpoints)
	}
	// First (https): should be checked + reachable.
	https := d.RUAEndpoints[0]
	if https.Scheme != "https" || !https.Checked || !https.Reachable {
		t.Fatalf("https endpoint not as expected: %+v", https)
	}
	// Second (mailto): scheme=mailto, not checked.
	mailto := d.RUAEndpoints[1]
	if mailto.Scheme != "mailto" || mailto.Checked {
		t.Fatalf("mailto endpoint should not be probed: %+v", mailto)
	}
}

func TestRun_RUAUnreachable_HTTPS(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_dmarc.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; p=reject; rua=https://reports.example.com/dmarc"},
	}
	p := New(m, false)
	p.HTTP = stubFetcher{status: 503}
	p.EnableRUACheck = true
	f := p.Run(context.Background(), "example.com")[0]
	d := f.Details.(Details)
	if d.RUAEndpoints[0].Reachable {
		t.Fatalf("503 should not be considered reachable: %+v", d.RUAEndpoints[0])
	}
}

func TestRun_RUACheckDisabled(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_dmarc.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; p=reject; rua=https://reports.example.com/dmarc"},
	}
	p := New(m, false)
	p.EnableRUACheck = false
	f := p.Run(context.Background(), "example.com")[0]
	d := f.Details.(Details)
	if d.RUAEndpoints[0].Checked {
		t.Fatalf("disabled flag should suppress HEAD: %+v", d.RUAEndpoints[0])
	}
}

func TestRun_MissingPolicyTag(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_dmarc.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; rua=mailto:dmarc@example.com"},
	}
	p := New(m, false)
	p.EnableRUACheck = false
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}
