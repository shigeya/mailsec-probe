// Package mtatls observes the SMTP STARTTLS posture of a domain's
// MX hosts and validates DANE/TLSA records against the certificates
// presented. It runs only when --active is set; it opens real TCP
// connections to port 25 and is therefore opt-in by design.
//
// Ethics: we EHLO with a name that identifies us, never send mail,
// QUIT cleanly, and respect a tight per-host timeout.
package mtatls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// MXProbeResult captures what one connection attempt to one MX host
// observed. All fields are zero-valued when ConnectErr is non-empty.
type MXProbeResult struct {
	Host               string
	Port               int
	Connected          bool
	ConnectErr         string
	BannerLine         string
	EHLOCapabilities   []string
	STARTTLSAdvertised bool
	STARTTLSAccepted   bool
	TLSVersion         uint16
	TLSCipherSuite     uint16
	PeerCertificates   []*x509.Certificate
	TLSErr             string
	DurationMs         int64
}

// Dialer probes one MX host. Implementations must respect ctx and
// must close the underlying socket before returning.
type Dialer interface {
	Probe(ctx context.Context, host string, port int, ourName string) MXProbeResult
}

// NewDialer returns the production Dialer using net/smtp and crypto/tls.
func NewDialer(perHostTimeout time.Duration) Dialer {
	if perHostTimeout <= 0 {
		perHostTimeout = 10 * time.Second
	}
	return &smtpDialer{timeout: perHostTimeout}
}

type smtpDialer struct {
	timeout time.Duration
}

func (s *smtpDialer) Probe(ctx context.Context, host string, port int, ourName string) MXProbeResult {
	r := MXProbeResult{Host: host, Port: port}
	start := time.Now()
	defer func() {
		r.DurationMs = time.Since(start).Milliseconds()
	}()

	address := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		r.ConnectErr = err.Error()
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	r.Connected = true
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		r.ConnectErr = "smtp.NewClient: " + err.Error()
		return r
	}
	defer func() { _ = cl.Quit() }()

	if err := cl.Hello(ourName); err != nil {
		r.ConnectErr = "EHLO: " + err.Error()
		return r
	}

	// Capabilities are advertised in the EHLO response; net/smtp does
	// not surface the full list, but Extension() lets us check
	// well-known names. STARTTLS is the only one we care about.
	if ok, _ := cl.Extension("STARTTLS"); ok {
		r.STARTTLSAdvertised = true
		r.EHLOCapabilities = append(r.EHLOCapabilities, "STARTTLS")
	}

	if !r.STARTTLSAdvertised {
		return r
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// Do NOT short-circuit verification here: we want to OBSERVE
		// what the server presents, not fail the probe. Verification
		// status is recorded by callers from the chain we return.
		InsecureSkipVerify: true, //nolint:gosec // observation-only by design
	}
	if err := cl.StartTLS(tlsCfg); err != nil {
		r.TLSErr = err.Error()
		return r
	}

	state, ok := cl.TLSConnectionState()
	if !ok {
		r.TLSErr = "no TLS connection state after StartTLS"
		return r
	}
	r.STARTTLSAccepted = true
	r.TLSVersion = state.Version
	r.TLSCipherSuite = state.CipherSuite
	r.PeerCertificates = state.PeerCertificates
	return r
}

// VerifyChain runs PKIX verification with the system roots against the
// certificate chain that the server presented. The DNS name used for
// matching is the MX host (per RFC 7672 and the common operational
// practice for SMTP).
//
// Returns (verified, errString). verified=false means the chain is not
// trusted under standard PKIX, which is information (not a fatal error
// in observation mode).
func VerifyChain(chain []*x509.Certificate, mxHost string) (bool, string) {
	if len(chain) == 0 {
		return false, "no peer certificates"
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       strings.TrimSuffix(mxHost, "."),
		Intermediates: intermediates,
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// TLSVersionName turns a TLS version constant into a readable string.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
