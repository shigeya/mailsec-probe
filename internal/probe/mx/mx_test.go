package mx

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestRun_Present_SortedByPreference(t *testing.T) {
	m := dnsclient.NewMock()
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{
			{Host: "mx-secondary.example.com", Preference: 20},
			{Host: "mx-primary.example.com", Preference: 10},
		},
	}
	p := New(m)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if len(d.Hosts) != 2 {
		t.Fatalf("hosts = %#v", d.Hosts)
	}
	if d.Hosts[0].Preference != 10 || d.Hosts[0].Host != "mx-primary.example.com" {
		t.Fatalf("expected sorted ascending; got %+v", d.Hosts)
	}
}

func TestRun_Absent(t *testing.T) {
	m := dnsclient.NewMock()
	p := New(m)
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestSummary(t *testing.T) {
	cases := []struct {
		name string
		in   Details
		want string
	}{
		{
			name: "no hosts",
			in:   Details{},
			want: "no MX",
		},
		{
			name: "one host",
			in:   Details{Hosts: []Host{{Preference: 10, Host: "mx.example.com"}}},
			want: "10 mx.example.com",
		},
		{
			name: "three hosts",
			in: Details{Hosts: []Host{
				{Preference: 10, Host: "a"},
				{Preference: 20, Host: "b"},
				{Preference: 30, Host: "c"},
			}},
			want: "10 a, 20 b, +1 more",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Summary(); got != tc.want {
				t.Fatalf("Summary() = %q, want %q", got, tc.want)
			}
		})
	}
}
