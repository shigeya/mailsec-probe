package tlsrpt

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestRun_Present(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_smtp._tls.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if d.ReportingURIs != "mailto:tlsrpt@example.com" {
		t.Fatalf("rua = %q", d.ReportingURIs)
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

func TestRun_MissingRua_IsMisconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_smtp._tls.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=TLSRPTv1"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestSummary(t *testing.T) {
	if s := (Details{}).Summary(); s != "" {
		t.Fatalf("empty Summary should be empty, got %q", s)
	}
	if s := (Details{ReportingURIs: "mailto:x@y"}).Summary(); s != "rua=mailto:x@y" {
		t.Fatalf("Summary = %q", s)
	}
}
