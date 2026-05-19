package dnsclient

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// fakeDoH satisfies DoHResolver with a static response table keyed by
// (name, qtype). It is used to exercise the conversion path without
// standing up a DoH server.
type fakeDoH struct {
	respond func(name string, qtype uint16) (resolver.Response, error)
}

func (f *fakeDoH) Resolve(_ context.Context, name string, qtype uint16) (resolver.Response, error) {
	return f.respond(name, qtype)
}

func newDoHClient(t *testing.T, fn func(name string, qtype uint16) (resolver.Response, error)) Client {
	t.Helper()
	zone.RegisterHandlers()
	return NewDoH(&fakeDoH{respond: fn})
}

func mustRR(t *testing.T, label string, qtype uint16, value string) *zone.ResourceRecord {
	t.Helper()
	rrtype, err := types.RRTypeToString(qtype)
	if err != nil {
		t.Fatalf("RRTypeToString(%d): %v", qtype, err)
	}
	rr, err := zone.NewResourceRecord(label, 300, "IN", rrtype, value)
	if err != nil {
		t.Fatalf("NewResourceRecord(%s, %s, %q): %v", label, rrtype, value, err)
	}
	return rr
}

func TestDoHClient_LookupTXT_JoinsCharacterStrings(t *testing.T) {
	c := newDoHClient(t, func(name string, qtype uint16) (resolver.Response, error) {
		return resolver.Response{
			AD:    true,
			RCode: 0,
			Records: []*zone.ResourceRecord{
				mustRR(t, "example.com.", types.TypeTXT, `"v=spf1 " "include:_spf.example.com " "-all"`),
				mustRR(t, "example.com.", types.TypeTXT, `"v=DKIM1; p=ABC"`),
			},
		}, nil
	})
	got, err := c.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if !got.AD {
		t.Errorf("AD = false, want true")
	}
	if got.RCode != 0 {
		t.Errorf("RCode = %d, want 0", got.RCode)
	}
	wantRecords := []string{"v=spf1 include:_spf.example.com -all", "v=DKIM1; p=ABC"}
	if len(got.Records) != len(wantRecords) {
		t.Fatalf("Records = %v, want %v", got.Records, wantRecords)
	}
	for i, w := range wantRecords {
		if got.Records[i] != w {
			t.Errorf("Records[%d] = %q, want %q", i, got.Records[i], w)
		}
	}
}

func TestDoHClient_LookupTXT_HandlesEscapes(t *testing.T) {
	c := newDoHClient(t, func(_ string, _ uint16) (resolver.Response, error) {
		return resolver.Response{
			Records: []*zone.ResourceRecord{
				mustRR(t, "example.com.", types.TypeTXT, `"foo\"bar" "baz\\qux"`),
			},
		}, nil
	})
	got, err := c.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	want := `foo"barbaz\qux`
	if len(got.Records) != 1 || got.Records[0] != want {
		t.Errorf("Records = %v, want [%q]", got.Records, want)
	}
}

func TestDoHClient_LookupTXT_PropagatesRCode(t *testing.T) {
	c := newDoHClient(t, func(_ string, _ uint16) (resolver.Response, error) {
		return resolver.Response{RCode: 3}, nil // NXDOMAIN
	})
	got, err := c.LookupTXT(context.Background(), "missing.example")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if got.RCode != 3 {
		t.Errorf("RCode = %d, want 3", got.RCode)
	}
	if len(got.Records) != 0 {
		t.Errorf("Records = %v, want empty", got.Records)
	}
}

func TestDoHClient_LookupTXT_PropagatesError(t *testing.T) {
	sentinel := errors.New("transport boom")
	c := newDoHClient(t, func(_ string, _ uint16) (resolver.Response, error) {
		return resolver.Response{}, sentinel
	})
	_, err := c.LookupTXT(context.Background(), "example.com")
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

func TestDoHClient_LookupMX_OrdersByPresentation(t *testing.T) {
	c := newDoHClient(t, func(_ string, _ uint16) (resolver.Response, error) {
		return resolver.Response{
			Records: []*zone.ResourceRecord{
				mustRR(t, "example.com.", types.TypeMX, "10 mail1.example.com."),
				mustRR(t, "example.com.", types.TypeMX, "20 mail2.example.com."),
			},
		}, nil
	})
	got, err := c.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("Records = %v, want 2", got.Records)
	}
	if got.Records[0].Preference != 10 || got.Records[0].Host != "mail1.example.com" {
		t.Errorf("Records[0] = %+v", got.Records[0])
	}
	if got.Records[1].Preference != 20 || got.Records[1].Host != "mail2.example.com" {
		t.Errorf("Records[1] = %+v", got.Records[1])
	}
}

func TestDoHClient_LookupTLSA_DecodesViaHandler(t *testing.T) {
	hexData := "abcd1234"
	want, _ := hex.DecodeString(hexData)
	c := newDoHClient(t, func(_ string, _ uint16) (resolver.Response, error) {
		return resolver.Response{
			Records: []*zone.ResourceRecord{
				mustRR(t, "_25._tcp.mail.example.com.", types.TypeTLSA, "3 1 1 "+hexData),
			},
		}, nil
	})
	got, err := c.LookupTLSA(context.Background(), "_25._tcp.mail.example.com")
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("Records = %d, want 1", len(got.Records))
	}
	r := got.Records[0]
	if r.Usage != 3 || r.Selector != 1 || r.MatchingType != 1 {
		t.Errorf("usage/selector/mt = %d/%d/%d, want 3/1/1", r.Usage, r.Selector, r.MatchingType)
	}
	if string(r.Data) != string(want) {
		t.Errorf("Data = %x, want %x", r.Data, want)
	}
}

func TestDoHClient_HasDS(t *testing.T) {
	c := newDoHClient(t, func(_ string, qtype uint16) (resolver.Response, error) {
		if qtype != types.TypeDS {
			t.Errorf("HasDS issued qtype %d, want DS", qtype)
		}
		return resolver.Response{
			Records: []*zone.ResourceRecord{
				mustRR(t, "example.com.", types.TypeDS, "12345 8 2 "+hexZeroBytes(32)),
			},
		}, nil
	})
	ok, err := c.HasDS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("HasDS: %v", err)
	}
	if !ok {
		t.Errorf("HasDS = false, want true")
	}
}

func TestDoHClient_HasDS_AbsentReturnsFalse(t *testing.T) {
	c := newDoHClient(t, func(_ string, _ uint16) (resolver.Response, error) {
		return resolver.Response{}, nil
	})
	ok, err := c.HasDS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("HasDS: %v", err)
	}
	if ok {
		t.Errorf("HasDS = true, want false")
	}
}

func TestDecodeTXTPresentation(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`"hello"`, "hello", true},
		{`"foo" "bar"`, "foobar", true},
		{`"a\"b"`, `a"b`, true},
		{`"a\\b"`, `a\b`, true},
		{`unquoted`, "", false},
		{`"unterminated`, "", false},
		{``, "", true},
	}
	for _, tc := range cases {
		got, ok := decodeTXTPresentation(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("decodeTXTPresentation(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDecodeMXPresentation(t *testing.T) {
	cases := []struct {
		in       string
		wantPref uint16
		wantHost string
		ok       bool
	}{
		{"10 mail.example.com.", 10, "mail.example.com", true},
		{"0 .", 0, "", false}, // empty exchange after trimming dot
		{"abc mail.example.com.", 0, "", false},
		{"10", 0, "", false},
	}
	for _, tc := range cases {
		got, ok := decodeMXPresentation(tc.in)
		if ok != tc.ok || got.Preference != tc.wantPref || got.Host != tc.wantHost {
			t.Errorf("decodeMXPresentation(%q) = (%+v, %v), want pref=%d host=%q ok=%v", tc.in, got, ok, tc.wantPref, tc.wantHost, tc.ok)
		}
	}
}

func TestIsDoHURL(t *testing.T) {
	for _, in := range []string{"https://cloudflare-dns.com/dns-query", "http://localhost:8053/q"} {
		if !IsDoHURL(in) {
			t.Errorf("IsDoHURL(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"1.1.1.1", "1.1.1.1:53", "8.8.8.8:53", ""} {
		if IsDoHURL(in) {
			t.Errorf("IsDoHURL(%q) = true, want false", in)
		}
	}
}

// hexZeroBytes returns "00..." of 2*n hex chars; tiny helper for fixtures.
func hexZeroBytes(n int) string {
	b := make([]byte, n)
	return hex.EncodeToString(b)
}
