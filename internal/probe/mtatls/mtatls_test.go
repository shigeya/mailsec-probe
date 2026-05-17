package mtatls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

// generateCert returns a freshly-minted self-signed cert and its parsed
// x509.Certificate, suitable for SHA-256/512 hashing in tests.
func generateCert(t *testing.T, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// stubDialer always returns the configured MXProbeResult, regardless of
// which host it was asked to probe.
type stubDialer struct {
	result MXProbeResult
}

func (s stubDialer) Probe(_ context.Context, host string, port int, _ string) MXProbeResult {
	r := s.result
	r.Host = host
	r.Port = port
	return r
}

func newProbe(mock *dnsclient.Mock, dialer Dialer) *Probe {
	return &Probe{
		DNS: mock, Dialer: dialer,
		Port: 25, OurName: "test.local", Concurrency: 2,
	}
}

func TestRun_NoMX_BothFeaturesAbsent(t *testing.T) {
	m := dnsclient.NewMock()
	p := newProbe(m, stubDialer{})
	feats := p.Run(context.Background(), "example.com")
	if len(feats) != 2 {
		t.Fatalf("expected 2 features, got %d", len(feats))
	}
	for _, f := range feats {
		if f.Status != signals.StatusAbsent {
			t.Errorf("feature %s = %s, want absent", f.Name, f.Status)
		}
	}
}

func TestRun_NullMX_BothFeaturesAbsent(t *testing.T) {
	m := dnsclient.NewMock()
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{{Host: "", Preference: 0}},
	}
	p := newProbe(m, stubDialer{})
	feats := p.Run(context.Background(), "example.com")
	for _, f := range feats {
		if f.Status != signals.StatusAbsent {
			t.Errorf("feature %s = %s, want absent (null MX)", f.Name, f.Status)
		}
	}
}

func TestRun_STARTTLSAcceptedAllMX(t *testing.T) {
	cert := generateCert(t, "mx.example.com")
	m := dnsclient.NewMock()
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{
			{Host: "mx.example.com", Preference: 10},
		},
	}
	dialer := stubDialer{result: MXProbeResult{
		Connected:          true,
		STARTTLSAdvertised: true,
		STARTTLSAccepted:   true,
		TLSVersion:         0x0304, // TLS 1.3
		PeerCertificates:   []*x509.Certificate{cert},
	}}
	p := newProbe(m, dialer)
	feats := p.Run(context.Background(), "example.com")

	var starttls *signals.Feature
	for i := range feats {
		if feats[i].Name == "starttls" {
			starttls = &feats[i]
		}
	}
	if starttls == nil {
		t.Fatal("starttls feature missing")
	}
	if starttls.Status != signals.StatusPresent {
		t.Fatalf("starttls = %s, want present", starttls.Status)
	}
	d := starttls.Details.(STARTTLSDetails)
	if len(d.MXResults) != 1 || !d.MXResults[0].STARTTLSAccepted {
		t.Fatalf("mx_results = %+v", d.MXResults)
	}
}

func TestRun_STARTTLSPartial_IsMisconfigured(t *testing.T) {
	// One MX accepts, one doesn't. We use two MX hosts mapped to the
	// same stub result for simplicity; the simpler way is to fail on
	// the second host. Use a per-host stub here.
	type perHostDialer struct {
		results map[string]MXProbeResult
	}
	m := dnsclient.NewMock()
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{
			{Host: "mx1.example.com", Preference: 10},
			{Host: "mx2.example.com", Preference: 20},
		},
	}
	dialer := perHostStubDialer{
		results: map[string]MXProbeResult{
			"mx1.example.com": {Connected: true, STARTTLSAdvertised: true, STARTTLSAccepted: true, TLSVersion: 0x0304},
			"mx2.example.com": {Connected: true, STARTTLSAdvertised: false, STARTTLSAccepted: false},
		},
	}
	p := newProbe(m, dialer)
	feats := p.Run(context.Background(), "example.com")
	for _, f := range feats {
		if f.Name == "starttls" && f.Status != signals.StatusMisconfigured {
			t.Fatalf("starttls = %s, want misconfigured (partial)", f.Status)
		}
	}
	_ = perHostDialer{} // touch to keep the compiler quiet about the unused embedded type below
}

type perHostStubDialer struct {
	results map[string]MXProbeResult
}

func (s perHostStubDialer) Probe(_ context.Context, host string, port int, _ string) MXProbeResult {
	r := s.results[host]
	r.Host = host
	r.Port = port
	return r
}

func TestRun_DANEMatchesSHA256SPKI(t *testing.T) {
	cert := generateCert(t, "mx.example.com")
	// Compute SHA-256 over SubjectPublicKeyInfo.
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	m := dnsclient.NewMock()
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{{Host: "mx.example.com", Preference: 10}},
	}
	m.TLSA["_25._tcp.mx.example.com"] = dnsclient.TLSAResult{
		Records: []dnsclient.TLSARecord{
			{Usage: 3, Selector: 1, MatchingType: 1, Data: spkiHash[:]},
		},
	}
	dialer := stubDialer{result: MXProbeResult{
		Connected: true, STARTTLSAdvertised: true, STARTTLSAccepted: true,
		PeerCertificates: []*x509.Certificate{cert},
	}}
	p := newProbe(m, dialer)
	feats := p.Run(context.Background(), "example.com")
	var dane *signals.Feature
	for i := range feats {
		if feats[i].Name == "dane" {
			dane = &feats[i]
		}
	}
	if dane == nil || dane.Status != signals.StatusPresent {
		t.Fatalf("dane = %+v, want present", dane)
	}
}

func TestRun_DANEMismatch_IsMisconfigured(t *testing.T) {
	cert := generateCert(t, "mx.example.com")
	bogusHash := sha256.Sum256([]byte("not the real spki"))

	m := dnsclient.NewMock()
	m.MX["example.com"] = dnsclient.MXResult{
		Records: []dnsclient.MX{{Host: "mx.example.com", Preference: 10}},
	}
	m.TLSA["_25._tcp.mx.example.com"] = dnsclient.TLSAResult{
		Records: []dnsclient.TLSARecord{
			{Usage: 3, Selector: 1, MatchingType: 1, Data: bogusHash[:]},
		},
	}
	dialer := stubDialer{result: MXProbeResult{
		Connected: true, STARTTLSAdvertised: true, STARTTLSAccepted: true,
		PeerCertificates: []*x509.Certificate{cert},
	}}
	p := newProbe(m, dialer)
	feats := p.Run(context.Background(), "example.com")
	for _, f := range feats {
		if f.Name == "dane" && f.Status != signals.StatusMisconfigured {
			t.Fatalf("dane = %s, want misconfigured", f.Status)
		}
	}
}

func TestMatchTLSA_AllMatchingTypes(t *testing.T) {
	cert := generateCert(t, "mx.example.com")
	chain := []*x509.Certificate{cert}

	cases := []struct {
		name string
		rec  dnsclient.TLSARecord
		want bool
	}{
		{
			name: "exact full cert",
			rec:  dnsclient.TLSARecord{Selector: 0, MatchingType: 0, Data: cert.Raw},
			want: true,
		},
		{
			name: "sha256 spki match",
			rec:  func() dnsclient.TLSARecord { h := sha256.Sum256(cert.RawSubjectPublicKeyInfo); return dnsclient.TLSARecord{Selector: 1, MatchingType: 1, Data: h[:]} }(),
			want: true,
		},
		{
			name: "sha512 spki match",
			rec:  func() dnsclient.TLSARecord { h := sha512.Sum512(cert.RawSubjectPublicKeyInfo); return dnsclient.TLSARecord{Selector: 1, MatchingType: 2, Data: h[:]} }(),
			want: true,
		},
		{
			name: "sha256 wrong",
			rec:  dnsclient.TLSARecord{Selector: 1, MatchingType: 1, Data: []byte{0x00}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchTLSA([]dnsclient.TLSARecord{tc.rec}, chain) >= 0
			if got != tc.want {
				t.Fatalf("matchTLSA = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifyChain_NoCerts(t *testing.T) {
	ok, msg := VerifyChain(nil, "mx.example.com")
	if ok || msg == "" {
		t.Fatalf("expected failure for empty chain")
	}
}
