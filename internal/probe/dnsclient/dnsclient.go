// Package dnsclient provides a shared DNS client used by every probe.
//
// The Client interface is intentionally small so tests can substitute a
// deterministic mock without touching the network. The default
// implementation wraps github.com/miekg/dns.
package dnsclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TXTResult is the per-name result of a TXT lookup.
//
// Records holds each individual TXT record (one string per record). For
// DNS TXT records made of multiple character-strings, those strings are
// joined (per RFC 6376 / 7208 reassembly rules) into a single record.
// AD is true if the response had the AD (Authenticated Data) bit set,
// indicating the resolver verified DNSSEC.
type TXTResult struct {
	Records []string
	AD      bool
	RCode   int
}

// MXResult is the result of an MX lookup.
type MXResult struct {
	Records []MX
	AD      bool
	RCode   int
}

// MX is a single MX RR.
type MX struct {
	Host       string
	Preference uint16
}

// TLSAResult is the result of a TLSA lookup.
type TLSAResult struct {
	Records []TLSARecord
	AD      bool
	RCode   int
}

// TLSARecord is a single TLSA RR (RFC 6698). Data is the binary
// certificate-association payload (not hex-encoded).
type TLSARecord struct {
	Usage        uint8 // 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE
	Selector     uint8 // 0=Cert, 1=SPKI
	MatchingType uint8 // 0=Full, 1=SHA-256, 2=SHA-512
	Data         []byte
}

// Client is the minimal DNS surface used by probes.
type Client interface {
	LookupTXT(ctx context.Context, name string) (TXTResult, error)
	LookupMX(ctx context.Context, name string) (MXResult, error)
	LookupTLSA(ctx context.Context, name string) (TLSAResult, error)
	HasDS(ctx context.Context, name string) (bool, error)
}

// Config controls the default Client.
type Config struct {
	// Server selects the transport:
	//   - empty: system resolver via /etc/resolv.conf (UDP/TCP)
	//   - "host" or "host:port": classic UDP/TCP resolver
	//   - "https://…" or "http://…": DoH backend pointed at this URL
	Server  string
	Timeout time.Duration
}

// New returns a default Client. The transport is chosen from
// [Config.Server]: a DoH URL (https://…) dispatches to the DoH backend
// shared with the DNSSEC verifier; anything else uses the UDP/TCP
// resolver wrapping miekg/dns.
func New(cfg Config) (Client, error) {
	if IsDoHURL(cfg.Server) {
		return NewDoHFromURL(cfg.Server)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	servers := []string{}
	if cfg.Server != "" {
		servers = append(servers, ensurePort(cfg.Server))
	} else {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err == nil {
			for _, s := range conf.Servers {
				servers = append(servers, net.JoinHostPort(s, conf.Port))
			}
		}
		if len(servers) == 0 {
			// Last-resort fallback when /etc/resolv.conf is unavailable.
			servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
		}
	}

	return &client{
		servers: servers,
		timeout: timeout,
	}, nil
}

type client struct {
	servers []string
	timeout time.Duration
}

func (c *client) LookupTXT(ctx context.Context, name string) (TXTResult, error) {
	msg, err := c.exchange(ctx, name, dns.TypeTXT)
	if err != nil {
		return TXTResult{}, err
	}
	out := TXTResult{
		AD:    msg.AuthenticatedData,
		RCode: msg.Rcode,
	}
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out.Records = append(out.Records, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

func (c *client) LookupMX(ctx context.Context, name string) (MXResult, error) {
	msg, err := c.exchange(ctx, name, dns.TypeMX)
	if err != nil {
		return MXResult{}, err
	}
	out := MXResult{
		AD:    msg.AuthenticatedData,
		RCode: msg.Rcode,
	}
	for _, rr := range msg.Answer {
		if m, ok := rr.(*dns.MX); ok {
			out.Records = append(out.Records, MX{
				Host:       strings.TrimSuffix(m.Mx, "."),
				Preference: m.Preference,
			})
		}
	}
	return out, nil
}

func (c *client) LookupTLSA(ctx context.Context, name string) (TLSAResult, error) {
	msg, err := c.exchange(ctx, name, dns.TypeTLSA)
	if err != nil {
		return TLSAResult{}, err
	}
	out := TLSAResult{
		AD:    msg.AuthenticatedData,
		RCode: msg.Rcode,
	}
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			data, herr := hexDecode(t.Certificate)
			if herr != nil {
				continue
			}
			out.Records = append(out.Records, TLSARecord{
				Usage:        t.Usage,
				Selector:     t.Selector,
				MatchingType: t.MatchingType,
				Data:         data,
			})
		}
	}
	return out, nil
}

func (c *client) HasDS(ctx context.Context, name string) (bool, error) {
	msg, err := c.exchange(ctx, name, dns.TypeDS)
	if err != nil {
		return false, err
	}
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.DS); ok {
			return true, nil
		}
	}
	return false, nil
}

func (c *client) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if len(c.servers) == 0 {
		return nil, errors.New("dnsclient: no servers configured")
	}
	dctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true) // DO bit so AD has meaning
	m.RecursionDesired = true
	m.AuthenticatedData = true // ask validating resolvers to set AD on responses

	udp := &dns.Client{Net: "udp", Timeout: c.timeout}
	tcp := &dns.Client{Net: "tcp", Timeout: c.timeout}
	var lastErr error
	for _, server := range c.servers {
		resp, _, err := udp.ExchangeContext(dctx, m, server)
		if err == nil && resp != nil && !resp.Truncated {
			return resp, nil
		}
		if err == nil && resp != nil && resp.Truncated {
			// Retry over TCP per RFC 5966.
			tresp, _, terr := tcp.ExchangeContext(dctx, m, server)
			if terr == nil && tresp != nil {
				return tresp, nil
			}
			lastErr = terr
			continue
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dnsclient: no answer from any server for %s", name)
	}
	return nil, lastErr
}

func ensurePort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// hexDecode converts the lower- or upper-case hex string the TLSA RR
// type carries in its Certificate field to bytes. Whitespace is
// tolerated. Returns an error on any non-hex character.
func hexDecode(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		clean = append(clean, c)
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length")
	}
	out := make([]byte, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		hi, ok1 := hexNibble(clean[i])
		lo, ok2 := hexNibble(clean[i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex character at %d", i)
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
