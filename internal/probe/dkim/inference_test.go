package dkim

import (
	"context"
	"sort"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
)

func TestLoadInferenceRules_Embedded(t *testing.T) {
	rules, err := LoadInferenceRules(nil)
	if err != nil {
		t.Fatalf("LoadInferenceRules: %v", err)
	}
	if len(rules) < 5 {
		t.Fatalf("expected substantial inference rule set, got %d", len(rules))
	}
}

func TestInferSelectorsFromSPF_NoSPF(t *testing.T) {
	m := dnsclient.NewMock()
	rules := []InferenceRule{
		{MatchInclude: "_spf.google.com", AddSelectors: []string{"google"}},
	}
	got := inferSelectorsFromSPF(context.Background(), m, "example.com", rules)
	if len(got) != 0 {
		t.Fatalf("expected no selectors when SPF absent, got %#v", got)
	}
}

func TestInferSelectorsFromSPF_Google(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 include:_spf.google.com ~all"},
	}
	rules := []InferenceRule{
		{MatchInclude: "_spf.google.com", AddSelectors: []string{"google", "20240617"}},
		{MatchInclude: "amazonses.com", AddSelectors: []string{"amazonses"}},
	}
	got := inferSelectorsFromSPF(context.Background(), m, "example.com", rules)
	sort.Strings(got)
	want := []string{"20240617", "google"}
	if !equalStrings(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestInferSelectorsFromSPF_MultipleProviders(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 include:_spf.google.com include:mailgun.org ~all"},
	}
	rules := []InferenceRule{
		{MatchInclude: "_spf.google.com", AddSelectors: []string{"google"}},
		{MatchInclude: "mailgun.org", AddSelectors: []string{"mg", "mta"}},
	}
	got := inferSelectorsFromSPF(context.Background(), m, "example.com", rules)
	sort.Strings(got)
	want := []string{"google", "mg", "mta"}
	if !equalStrings(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestInferSelectorsFromSPF_RedirectAlsoMatches(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 redirect=_spf.google.com"},
	}
	rules := []InferenceRule{
		{MatchInclude: "_spf.google.com", AddSelectors: []string{"google"}},
	}
	got := inferSelectorsFromSPF(context.Background(), m, "example.com", rules)
	if len(got) != 1 || got[0] != "google" {
		t.Fatalf("redirect= should also match: got %#v", got)
	}
}

func TestRun_InferenceMergesIntoSelectors(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["example.com"] = dnsclient.TXTResult{
		Records: []string{"v=spf1 include:_spf.google.com -all"},
	}
	m.TXT["20240617._domainkey.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DKIM1; k=rsa; p=MIIB"},
	}
	p, err := New(m, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// Strip default selectors so the test focuses on inference only.
	p.Selectors = []string{}
	f := p.Run(context.Background(), "example.com")[0]
	d := f.Details.(Details)
	foundInferred := false
	for _, s := range d.SelectorsInferred {
		if s == "20240617" {
			foundInferred = true
		}
	}
	if !foundInferred {
		t.Fatalf("expected 20240617 in inferred set: %#v", d.SelectorsInferred)
	}
	if len(d.SelectorsFound) == 0 || d.SelectorsFound[0] != "20240617" {
		t.Fatalf("expected hit at 20240617: %#v", d.SelectorsFound)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
