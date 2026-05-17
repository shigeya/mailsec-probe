package spf

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestRun_PresentSoftfail(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 include:_spf.example.com ~all"},
	}
	p := New(m, true)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d, ok := f.Details.(Details)
	if !ok {
		t.Fatalf("details type = %T", f.Details)
	}
	if d.Qualifier != QualifierSoftfail {
		t.Fatalf("qualifier = %s", d.Qualifier)
	}
	if len(d.Includes) != 1 || d.Includes[0] != "_spf.example.com" {
		t.Fatalf("includes = %#v", d.Includes)
	}
}

func TestRun_Absent(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"google-site-verification=abc"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_MultipleSPFIsMisconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{
			"v=spf1 -all",
			"v=spf1 include:_spf.example.com ~all",
		},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_PlusAllIsMisconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 +all"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_RedirectOnly_NotMisconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 redirect=_spf.parent.example"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s, want present (redirect delegates policy)", f.Status)
	}
	d := f.Details.(Details)
	if d.Redirect != "_spf.parent.example" {
		t.Fatalf("redirect = %q", d.Redirect)
	}
}

func TestRun_RedirectMechanism(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 redirect=_spf.parent.example -all"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")
	d := f.Details.(Details)
	if d.Redirect != "_spf.parent.example" {
		t.Fatalf("redirect = %q", d.Redirect)
	}
	if d.Qualifier != QualifierFail {
		t.Fatalf("qualifier = %s", d.Qualifier)
	}
}

func TestIsSPF(t *testing.T) {
	cases := map[string]bool{
		"v=spf1":                  true,
		"v=spf1 -all":             true,
		"V=SPF1 ~all":             true,
		"v=spf1foo":               false,
		"":                        false,
		"google-site-verification": false,
	}
	for in, want := range cases {
		if got := isSPF(in); got != want {
			t.Errorf("isSPF(%q) = %v, want %v", in, got, want)
		}
	}
}
