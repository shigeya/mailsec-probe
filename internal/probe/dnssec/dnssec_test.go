package dnssec

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestRun_DSAndAD(t *testing.T) {
	m := dnsclient.NewMock()
	m.DS["example.com"] = true
	m.TXT["example.com"] = dnsclient.TXTResult{Records: []string{"hello"}, AD: true}
	p := New(m)
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	if f.Confidence < 0.99 {
		t.Fatalf("confidence = %v, want highest", f.Confidence)
	}
	if (f.Details.(Details)).Summary() != "DS + AD" {
		t.Fatalf("summary = %q", (f.Details.(Details)).Summary())
	}
}

func TestRun_DSOnly(t *testing.T) {
	m := dnsclient.NewMock()
	m.DS["example.com"] = true
	m.TXT["example.com"] = dnsclient.TXTResult{Records: []string{"hello"}, AD: false}
	p := New(m)
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	if f.Confidence >= 1.0 {
		t.Fatalf("confidence = %v, want < 1.0", f.Confidence)
	}
}

func TestRun_ADOnly(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{Records: []string{"hello"}, AD: true}
	p := New(m)
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestRun_Unsigned(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{Records: []string{"hello"}}
	p := New(m)
	f := p.Run(context.Background(), "example.com")[0]
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
	if (f.Details.(Details)).Summary() != "" {
		t.Fatalf("Summary on unsigned should be empty (formatter falls back to reason)")
	}
}

func TestSummary(t *testing.T) {
	cases := []struct {
		d    Details
		want string
	}{
		{Details{HasDS: true, ADBitOnTXT: true}, "DS + AD"},
		{Details{HasDS: true}, "DS only"},
		{Details{ADBitOnTXT: true}, "AD only"},
		{Details{}, ""},
	}
	for _, tc := range cases {
		if got := tc.d.Summary(); got != tc.want {
			t.Errorf("Summary(%+v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
