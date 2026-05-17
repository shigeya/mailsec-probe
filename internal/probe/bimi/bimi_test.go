package bimi

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestRun_PresentWithLogoAndVMC(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["default._bimi.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"},
	}
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if d.LogoURI != "https://example.com/logo.svg" {
		t.Fatalf("logo = %q", d.LogoURI)
	}
	if d.VMCURI != "https://example.com/vmc.pem" {
		t.Fatalf("vmc = %q", d.VMCURI)
	}
}

func TestRun_Absent(t *testing.T) {
	m := dnsclient.NewMock()
	p := New(m, false)
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_CustomSelector(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["custom._bimi.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=BIMI1; l=https://example.com/logo.svg"},
	}
	p := New(m, false)
	p.Selector = "custom"
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestSummary(t *testing.T) {
	cases := []struct {
		name string
		in   Details
		want string
	}{
		{name: "empty", in: Details{}, want: ""},
		{name: "logo only", in: Details{LogoURI: "https://e/l.svg"}, want: "logo=https://e/l.svg"},
		{name: "logo + vmc", in: Details{LogoURI: "https://e/l.svg", VMCURI: "https://e/v.pem"}, want: "logo=https://e/l.svg, vmc=yes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Summary(); got != tc.want {
				t.Fatalf("Summary() = %q, want %q", got, tc.want)
			}
		})
	}
}
