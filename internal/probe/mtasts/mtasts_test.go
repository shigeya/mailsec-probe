package mtasts

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

type stubHTTP struct {
	status int
	body   string
	err    error
}

func (s stubHTTP) Get(_ context.Context, _ string) (int, string, error) {
	return s.status, s.body, s.err
}

func newProbe(d dnsclient.Client, h HTTPFetcher) *Probe {
	return &Probe{DNS: d, HTTP: h, IncludeRaw: true}
}

func TestRun_PresentEnforce(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_mta-sts.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=STSv1; id=20240101000000Z"},
	}
	policy := strings.Join([]string{
		"version: STSv1",
		"mode: enforce",
		"mx: *.mail.example.com",
		"max_age: 604800",
	}, "\n")
	p := newProbe(m, stubHTTP{status: http.StatusOK, body: policy})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if d.Policy.Mode != "enforce" {
		t.Fatalf("mode = %s", d.Policy.Mode)
	}
	if len(d.Policy.MX) != 1 || d.Policy.MX[0] != "*.mail.example.com" {
		t.Fatalf("mx = %#v", d.Policy.MX)
	}
}

func TestRun_DNSOnly_Misconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_mta-sts.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=STSv1; id=20240101000000Z"},
	}
	p := newProbe(m, stubHTTP{status: http.StatusNotFound})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_Absent(t *testing.T) {
	m := dnsclient.NewMock()
	p := newProbe(m, stubHTTP{status: http.StatusNotFound})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_PolicyNoneIsMisconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_mta-sts.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=STSv1; id=2024"},
	}
	body := "version: STSv1\nmode: none\n"
	p := newProbe(m, stubHTTP{status: http.StatusOK, body: body})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}
