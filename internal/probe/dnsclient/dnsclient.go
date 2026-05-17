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

// Client is the minimal DNS surface used by probes.
type Client interface {
	LookupTXT(ctx context.Context, name string) (TXTResult, error)
	LookupMX(ctx context.Context, name string) (MXResult, error)
	HasDS(ctx context.Context, name string) (bool, error)
}

// Config controls the default Client.
type Config struct {
	// Server is the DNS server to query, host:port. Empty means use the
	// system resolver via miekg/dns ClientConfigFromFile fallback.
	Server  string
	Timeout time.Duration
}

// New returns a default Client that queries Server (or system resolvers
// if Server is empty).
func New(cfg Config) (Client, error) {
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
