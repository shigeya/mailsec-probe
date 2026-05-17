// Package mtasts observes MTA-STS (RFC 8461):
//
//  1. A TXT record at _mta-sts.<domain> advertises a policy ID.
//  2. The policy itself is fetched over HTTPS from
//     https://mta-sts.<domain>/.well-known/mta-sts.txt
//
// The TXT publishes the policy id and version. The HTTPS body is a
// key/value document (one per line) with mode, mx, and max_age.
package mtasts

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/probe/txttag"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const (
	name        = "mta-sts"
	defaultUA   = "mailsec-probe/0.1 (+https://github.com/shigeya/mailsec-probe)"
	defaultPath = "/.well-known/mta-sts.txt"
)

// HTTPFetcher is the minimal HTTPS surface mtasts needs.
// Tests substitute a stub; production uses http.Client.
type HTTPFetcher interface {
	Get(ctx context.Context, url string) (status int, body string, err error)
}

// Probe observes MTA-STS.
type Probe struct {
	DNS        dnsclient.Client
	HTTP       HTTPFetcher
	UserAgent  string
	IncludeRaw bool
}

// New constructs a Probe with a default HTTPS fetcher.
func New(d dnsclient.Client, includeRaw bool) *Probe {
	return &Probe{
		DNS:        d,
		HTTP:       NewHTTPFetcher(8*time.Second, defaultUA),
		UserAgent:  defaultUA,
		IncludeRaw: includeRaw,
	}
}

// Name returns the feature name.
func (*Probe) Name() string { return name }

// Policy is the parsed mta-sts.txt body.
type Policy struct {
	Version string   `json:"version,omitempty"`
	Mode    string   `json:"mode,omitempty"` // enforce / testing / none
	MX      []string `json:"mx,omitempty"`
	MaxAge  string   `json:"max_age,omitempty"`
	Raw     string   `json:"raw,omitempty"`
}

// Details is the structured MTA-STS detail payload.
type Details struct {
	DNSRecord struct {
		ID  string `json:"id,omitempty"`
		Raw string `json:"raw,omitempty"`
	} `json:"dns_record"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Policy     Policy `json:"policy,omitempty"`
}

// Run observes both the DNS marker and the HTTPS policy.
func (p *Probe) Run(ctx context.Context, domain string) signals.Feature {
	d := Details{}
	var sigs []signals.Signal
	var reasons []string

	// 1. DNS TXT
	dnsTarget := "_mta-sts." + domain
	dnsRes, dnsErr := p.DNS.LookupTXT(ctx, dnsTarget)
	dnsSig := signals.Signal{Source: signals.SourceDNSTxt, Target: dnsTarget, OK: dnsErr == nil}
	if dnsErr != nil {
		dnsSig.Err = dnsErr.Error()
	} else {
		dnsSig.Records = dnsRes.Records
	}
	sigs = append(sigs, dnsSig)

	var (
		dnsPresent bool
		dnsRaw     string
	)
	if dnsErr == nil {
		if raw, pairs, ok := txttag.PickByVersion(dnsRes.Records, "STSv1"); ok {
			dnsPresent = true
			dnsRaw = raw
			d.DNSRecord.ID = txttag.Get(pairs, "id")
			if p.IncludeRaw {
				d.DNSRecord.Raw = raw
			}
		}
	}
	_ = dnsRaw

	// 2. HTTPS policy
	httpsURL := "https://mta-sts." + domain + defaultPath
	httpsTarget := httpsURL
	status, body, httpErr := p.HTTP.Get(ctx, httpsURL)
	httpSig := signals.Signal{Source: signals.SourceHTTPSGet, Target: httpsTarget, OK: httpErr == nil && status == http.StatusOK}
	if httpErr != nil {
		httpSig.Err = httpErr.Error()
	}
	if status > 0 {
		httpSig.Meta = map[string]string{"status": fmt.Sprintf("%d", status)}
	}
	sigs = append(sigs, httpSig)

	var policyPresent bool
	if httpErr == nil && status == http.StatusOK {
		policy := parsePolicy(body)
		if p.IncludeRaw {
			policy.Raw = body
		}
		d.HTTPStatus = status
		d.Policy = policy
		if policy.Mode != "" || policy.Version != "" {
			policyPresent = true
		}
	} else if status > 0 {
		d.HTTPStatus = status
	}

	// 3. Decide overall status.
	switch {
	case dnsPresent && policyPresent:
		mode := d.Policy.Mode
		if mode == "" {
			mode = "(unspecified)"
		}
		reasons = append(reasons, "TXT _mta-sts present", "HTTPS policy present", "mode="+mode)
		st := signals.StatusPresent
		conf := 0.95
		if d.Policy.Mode == "none" {
			st = signals.StatusMisconfigured
			reasons = append(reasons, "policy mode=none (advertised but not enforced)")
		}
		return signals.Feature{
			Name: name, Status: st, Confidence: conf,
			Reasons: reasons, Details: d, Signals: sigs,
		}
	case dnsPresent && !policyPresent:
		return signals.Feature{
			Name: name, Status: signals.StatusMisconfigured, Confidence: 0.85,
			Reasons: []string{"_mta-sts TXT advertised but HTTPS policy missing"},
			Details: d, Signals: sigs,
		}
	case !dnsPresent && policyPresent:
		return signals.Feature{
			Name: name, Status: signals.StatusMisconfigured, Confidence: 0.6,
			Reasons: []string{"HTTPS policy present but no _mta-sts TXT"},
			Details: d, Signals: sigs,
		}
	default:
		return signals.Feature{
			Name: name, Status: signals.StatusAbsent, Confidence: 0.9,
			Reasons: []string{"no _mta-sts TXT and no HTTPS policy"},
			Details: d, Signals: sigs,
		}
	}
}

func parsePolicy(body string) Policy {
	p := Policy{}
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = strings.ToLower(value)
		case "max_age":
			p.MaxAge = value
		case "mx":
			p.MX = append(p.MX, value)
		}
	}
	return p
}

// --- default HTTP fetcher ---

// NewHTTPFetcher returns an HTTPFetcher that uses net/http.
func NewHTTPFetcher(timeout time.Duration, ua string) HTTPFetcher {
	if ua == "" {
		ua = defaultUA
	}
	return &httpFetcher{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		ua: ua,
	}
}

type httpFetcher struct {
	client *http.Client
	ua     string
}

func (h *httpFetcher) Get(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", h.ua)
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	// Cap body to 64 KB to avoid pathological inputs.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}
