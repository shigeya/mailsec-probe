package dkim

import (
	"context"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

func newProbeWithSelectors(t *testing.T, m dnsclient.Client, selectors []string) *Probe {
	t.Helper()
	p, err := New(m, nil, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.Selectors = selectors
	return p
}

func TestRun_PresentSingleSelector(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["google._domainkey.example.com"] = dnsclient.TXTResult{
		Records: []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxxxx"},
	}
	p := newProbeWithSelectors(t, m, []string{"google", "selector1"})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if len(d.SelectorsFound) != 1 || d.SelectorsFound[0] != "google" {
		t.Fatalf("found = %#v", d.SelectorsFound)
	}
	if len(d.Keys) != 1 || d.Keys[0].KeyType != "rsa" {
		t.Fatalf("keys = %#v", d.Keys)
	}
}

func TestRun_AbsentAllTried(t *testing.T) {
	m := dnsclient.NewMock()
	p := newProbeWithSelectors(t, m, []string{"default", "google", "selector1"})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusAbsent {
		t.Fatalf("status = %s", f.Status)
	}
	d := f.Details.(Details)
	if len(d.SelectorsTried) != 3 {
		t.Fatalf("tried = %#v", d.SelectorsTried)
	}
}

func TestRun_AcceptsRecordWithoutVTag(t *testing.T) {
	m := dnsclient.NewMock()
	m.TXT["selector1._domainkey.example.com"] = dnsclient.TXTResult{
		// Some operators publish DKIM keys without the v=DKIM1 prefix.
		Records: []string{"k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"},
	}
	p := newProbeWithSelectors(t, m, []string{"selector1"})
	f := p.Run(context.Background(), "example.com")
	if f.Status != signals.StatusPresent {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestLoadSelectors_Embedded(t *testing.T) {
	sel, err := LoadSelectors(nil)
	if err != nil {
		t.Fatalf("LoadSelectors: %v", err)
	}
	if len(sel) < 10 {
		t.Fatalf("expected substantial default selector list, got %d", len(sel))
	}
}
