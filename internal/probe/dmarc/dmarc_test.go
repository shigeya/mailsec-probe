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
	f := p.Run(context.Background(), "example.com")
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
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_MissingPolicyTag(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_dmarc.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DMARC1; rua=mailto:dmarc@example.com"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}
