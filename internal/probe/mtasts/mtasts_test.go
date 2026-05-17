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

func (s stubHTTP) Head(_ context.Context, _ string) (int, error) {
	return s.status, s.err
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

func TestRun_PolicyMXMismatch_IsMisconfigured(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_mta-sts.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=STSv1; id=2024"},
	}
	// Real MX = something.outside-policy.com, but policy only permits *.mail.example.com.
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{
			{Host: "mx.outside-policy.com", Preference: 10},
		},
	}
	body := "version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmax_age: 86400\n"
	p := newProbe(m, stubHTTP{status: http.StatusOK, body: body})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusMisconfigured {
		t.Fatalf("status = %s, want misconfigured (MX outside policy)", f.Status)
	}
	d := f.Details.(Details)
	if d.MXMatch == nil || d.MXMatch.AllMatched {
		t.Fatalf("expected unmatched MX detection: %+v", d.MXMatch)
	}
	if len(d.MXMatch.Unmatched) != 1 || d.MXMatch.Unmatched[0] != "mx.outside-policy.com" {
		t.Fatalf("unmatched = %#v", d.MXMatch.Unmatched)
	}
}

func TestRun_PolicyMXMatch_IsPresent(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["_mta-sts.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=STSv1; id=2024"},
	}
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{
			{Host: "mx1.mail.example.com", Preference: 10},
			{Host: "mx2.mail.example.com", Preference: 20},
		},
	}
	body := "version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmax_age: 86400\n"
	p := newProbe(m, stubHTTP{status: http.StatusOK, body: body})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s, want present", f.Status)
	}
	d := f.Details.(Details)
	if d.MXMatch == nil || !d.MXMatch.AllMatched {
		t.Fatalf("expected all matched: %+v", d.MXMatch)
	}
}

func TestCompareMXAgainstPolicy(t *testing.T) {
	cases := []struct {
		name     string
		hosts    []string
		patterns []string
		want     bool
	}{
		{name: "exact match", hosts: []string{"mx.example.com"}, patterns: []string{"mx.example.com"}, want: true},
		{name: "wildcard single label", hosts: []string{"mx1.mail.example.com"}, patterns: []string{"*.mail.example.com"}, want: true},
		{name: "wildcard does not match multiple labels", hosts: []string{"a.b.mail.example.com"}, patterns: []string{"*.mail.example.com"}, want: false},
		{name: "wildcard does not match suffix itself", hosts: []string{"mail.example.com"}, patterns: []string{"*.mail.example.com"}, want: false},
		{name: "case insensitive", hosts: []string{"MX.EXAMPLE.COM"}, patterns: []string{"mx.example.com"}, want: true},
		{name: "trailing dot tolerated", hosts: []string{"mx.example.com."}, patterns: []string{"mx.example.com"}, want: true},
		{name: "multiple patterns, second matches", hosts: []string{"mx.example.com"}, patterns: []string{"other.example.com", "mx.example.com"}, want: true},
		{name: "no match", hosts: []string{"foreign.example.com"}, patterns: []string{"*.mail.example.com"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := compareMXAgainstPolicy(tc.hosts, tc.patterns)
			if m.AllMatched != tc.want {
				t.Fatalf("AllMatched = %v, want %v; unmatched=%v", m.AllMatched, tc.want, m.Unmatched)
			}
		})
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
