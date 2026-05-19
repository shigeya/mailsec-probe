package dnsclient

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/resolver/doh"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// DoHResolver is the minimal subset of [doh.Client] this package
// depends on. Defining it as an interface keeps tests free of HTTP
// transport setup: a fake DoHResolver can be supplied directly.
type DoHResolver interface {
	Resolve(ctx context.Context, name string, qtype uint16) (resolver.Response, error)
}

// NewDoH returns a [Client] that issues DNS lookups over a shared
// [doh.Client]. The same DoH client can be passed to
// [github.com/shigeya/dnsdata-go/verifier]'s [verifier.ResolverFunc]
// so chain validation and probe lookups travel over a single HTTP/2
// connection.
func NewDoH(c DoHResolver) Client {
	return &dohClient{r: c}
}

// dohClient adapts the dnsdata-go resolver surface to the typed
// [Client] interface used by every probe. Wire-level decoding lives
// in dnsdata-go; this layer only re-shapes the presentation strings
// (and the cached TLSA handler) into the structs probes consume.
type dohClient struct {
	r DoHResolver
}

func (c *dohClient) LookupTXT(ctx context.Context, name string) (TXTResult, error) {
	resp, err := c.r.Resolve(ctx, name, types.TypeTXT)
	if err != nil {
		return TXTResult{}, err
	}
	out := TXTResult{
		AD:    resp.AD,
		RCode: int(resp.RCode),
	}
	for _, rr := range resp.Records {
		if rr.Type != types.TypeTXT {
			continue
		}
		joined, ok := decodeTXTPresentation(rr.Value)
		if !ok {
			// Skip records whose presentation form we cannot parse.
			// Reaching here implies a dnsdata-go regression; the
			// probe layer simply treats this record as absent.
			continue
		}
		out.Records = append(out.Records, joined)
	}
	return out, nil
}

func (c *dohClient) LookupMX(ctx context.Context, name string) (MXResult, error) {
	resp, err := c.r.Resolve(ctx, name, types.TypeMX)
	if err != nil {
		return MXResult{}, err
	}
	out := MXResult{
		AD:    resp.AD,
		RCode: int(resp.RCode),
	}
	for _, rr := range resp.Records {
		if rr.Type != types.TypeMX {
			continue
		}
		mx, ok := decodeMXPresentation(rr.Value)
		if !ok {
			continue
		}
		out.Records = append(out.Records, mx)
	}
	return out, nil
}

func (c *dohClient) LookupTLSA(ctx context.Context, name string) (TLSAResult, error) {
	resp, err := c.r.Resolve(ctx, name, types.TypeTLSA)
	if err != nil {
		return TLSAResult{}, err
	}
	out := TLSAResult{
		AD:    resp.AD,
		RCode: int(resp.RCode),
	}
	for _, rr := range resp.Records {
		if rr.Type != types.TypeTLSA {
			continue
		}
		h, ok := rr.Handler().(*zone.TLSA)
		if !ok {
			continue
		}
		out.Records = append(out.Records, TLSARecord{
			Usage:        h.Usage,
			Selector:     h.Selector,
			MatchingType: h.MatchingType,
			Data:         append([]byte(nil), h.CertificateAssociationData...),
		})
	}
	return out, nil
}

func (c *dohClient) HasDS(ctx context.Context, name string) (bool, error) {
	resp, err := c.r.Resolve(ctx, name, types.TypeDS)
	if err != nil {
		return false, err
	}
	for _, rr := range resp.Records {
		if rr.Type == types.TypeDS {
			return true, nil
		}
	}
	return false, nil
}

// decodeTXTPresentation reverses dnsdata-go's TXT presentation form
// (`"foo" "bar"` — each character-string quoted with `"` / `\` escaped
// and space-separated) into a single concatenated string. Matches the
// joining policy used by the UDP/TCP client at dnsclient.go (Records
// holds one entry per TXT RR, with multiple character-strings glued
// together per RFC 6376 §3.2 / RFC 7208 §3.3 reassembly).
//
// Returns ok=false when the input is not well-formed.
func decodeTXTPresentation(s string) (string, bool) {
	var out strings.Builder
	i := 0
	for i < len(s) {
		// Skip whitespace between character-strings.
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] != '"' {
			return "", false
		}
		i++ // consume opening quote
		for i < len(s) && s[i] != '"' {
			c := s[i]
			if c == '\\' {
				if i+1 >= len(s) {
					return "", false
				}
				c = s[i+1]
				i += 2
			} else {
				i++
			}
			out.WriteByte(c)
		}
		if i >= len(s) || s[i] != '"' {
			return "", false
		}
		i++ // consume closing quote
	}
	return out.String(), true
}

// decodeMXPresentation parses `"<preference> <exchange>"` (with the
// exchange always emitted as a fully-qualified name with trailing dot
// by dnsdata-go).
func decodeMXPresentation(s string) (MX, bool) {
	sp := strings.IndexByte(s, ' ')
	if sp <= 0 || sp == len(s)-1 {
		return MX{}, false
	}
	pref, err := strconv.ParseUint(strings.TrimSpace(s[:sp]), 10, 16)
	if err != nil {
		return MX{}, false
	}
	host := strings.TrimSpace(s[sp+1:])
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return MX{}, false
	}
	return MX{
		Host:       host,
		Preference: uint16(pref),
	}, true
}

// IsDoHURL reports whether s looks like a DoH endpoint URL. Used by
// [New] to dispatch between the legacy miekg/dns backend and the
// DoH-backed [dohClient].
func IsDoHURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// NewDoHFromURL is a small convenience: it builds a [doh.Client]
// pointed at the given provider URL and wraps it in a probe-shaped
// [Client]. Used by the CLI when `--dns-server` looks like a URL and
// the caller does not want to share the client with the verifier.
//
// Most production code should construct the [doh.Client] explicitly
// (so options like custom providers or http.Client survive) and call
// [NewDoH] directly to share the same instance with the DNSSEC
// verifier.
func NewDoHFromURL(url string) (Client, error) {
	if !IsDoHURL(url) {
		return nil, fmt.Errorf("dnsclient: %q is not a DoH URL", url)
	}
	return NewDoH(doh.NewClient(doh.WithProviders(url))), nil
}
