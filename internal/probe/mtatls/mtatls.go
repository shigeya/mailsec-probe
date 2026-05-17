package mtatls

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/internal/signals"
)

const (
	featureSTARTTLS = "starttls"
	featureDANE     = "dane"

	defaultPort        = 25
	defaultPerMXTimeout = 10 * time.Second
	defaultConcurrency = 4
	defaultEHLOName    = "mailsec-probe.local"
)

// Probe runs the active SMTP/TLS observation against a domain's MX hosts.
//
// One Run call emits TWO features:
//   - "starttls" — STARTTLS support, TLS version, cert chain summary
//   - "dane" — TLSA records at _25._tcp.<mx> + cert match result
type Probe struct {
	DNS         dnsclient.Client
	Dialer      Dialer
	Port        int
	OurName     string // EHLO name; identify ourselves honestly
	Concurrency int
	IncludeRaw  bool
}

// New constructs a Probe with sensible defaults.
func New(d dnsclient.Client) *Probe {
	return &Probe{
		DNS:         d,
		Dialer:      NewDialer(defaultPerMXTimeout),
		Port:        defaultPort,
		OurName:     defaultEHLOName,
		Concurrency: defaultConcurrency,
	}
}

// Name returns a stable identifier for logging. The probe actually
// emits two features (starttls and dane); the returned name is just
// for log lines.
func (*Probe) Name() string { return "mtatls" }

// STARTTLSDetails is the structured payload for the "starttls" feature.
type STARTTLSDetails struct {
	MXResults []MXSummary `json:"mx_results"`
}

// MXSummary collapses MXProbeResult to the fields useful in reports.
type MXSummary struct {
	Host               string `json:"host"`
	STARTTLSAdvertised bool   `json:"starttls_advertised"`
	STARTTLSAccepted   bool   `json:"starttls_accepted"`
	TLSVersion         string `json:"tls_version,omitempty"`
	LeafSubject        string `json:"leaf_subject,omitempty"`
	LeafIssuer         string `json:"leaf_issuer,omitempty"`
	LeafSANs           []string `json:"leaf_sans,omitempty"`
	NotBefore          string `json:"not_before,omitempty"`
	NotAfter           string `json:"not_after,omitempty"`
	PKIXValid          bool   `json:"pkix_valid"`
	PKIXErr            string `json:"pkix_err,omitempty"`
	ConnectErr         string `json:"connect_err,omitempty"`
	TLSErr             string `json:"tls_err,omitempty"`
	DurationMs         int64  `json:"duration_ms"`
}

// Summary returns a one-line human description for the STARTTLS feature.
func (d STARTTLSDetails) Summary() string {
	if len(d.MXResults) == 0 {
		return "no MX"
	}
	accepted, pkix, total := 0, 0, len(d.MXResults)
	versions := map[string]struct{}{}
	for _, r := range d.MXResults {
		if r.STARTTLSAccepted {
			accepted++
			if r.PKIXValid {
				pkix++
			}
			if r.TLSVersion != "" {
				versions[r.TLSVersion] = struct{}{}
			}
		}
	}
	vlist := make([]string, 0, len(versions))
	for v := range versions {
		vlist = append(vlist, v)
	}
	sort.Strings(vlist)
	return fmt.Sprintf("%d/%d MX STARTTLS, %d/%d PKIX-valid (%s)",
		accepted, total, pkix, accepted, strings.Join(vlist, "/"))
}

// DANEDetails is the structured payload for the "dane" feature.
type DANEDetails struct {
	MXResults []DANEMXResult `json:"mx_results"`
}

// DANEMXResult records the per-MX DANE outcome.
type DANEMXResult struct {
	Host        string       `json:"host"`
	Target      string       `json:"target"` // _25._tcp.<host>
	NumRecords  int          `json:"num_records"`
	Matched     bool         `json:"matched"`
	MatchedRR   string       `json:"matched_record,omitempty"`
	Records     []TLSAEntry  `json:"records,omitempty"`
	LookupErr   string       `json:"lookup_err,omitempty"`
}

// TLSAEntry is one TLSA record's human-readable triple.
type TLSAEntry struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
}

// Summary returns a one-line human description for the DANE feature.
// Returns empty when no TLSA exists anywhere; the formatter then falls
// back to the verdict reason instead of printing both.
func (d DANEDetails) Summary() string {
	if len(d.MXResults) == 0 {
		return ""
	}
	present, matched := 0, 0
	for _, r := range d.MXResults {
		if r.NumRecords > 0 {
			present++
			if r.Matched {
				matched++
			}
		}
	}
	if present == 0 {
		return ""
	}
	return fmt.Sprintf("%d/%d MX have TLSA, %d/%d validate", present, len(d.MXResults), matched, present)
}

// Run probes every MX host and returns both starttls and dane features.
func (p *Probe) Run(ctx context.Context, domain string) []signals.Feature {
	mxRes, err := p.DNS.LookupMX(ctx, domain)
	if err != nil {
		return []signals.Feature{
			{Name: featureSTARTTLS, Status: signals.StatusUnknown, Confidence: 0,
				Reasons: []string{"MX lookup failed: " + err.Error()}},
			{Name: featureDANE, Status: signals.StatusUnknown, Confidence: 0,
				Reasons: []string{"MX lookup failed: " + err.Error()}},
		}
	}
	if len(mxRes.Records) == 0 || isNullMX(mxRes.Records) {
		reason := "no MX records"
		if isNullMX(mxRes.Records) {
			reason = "null MX (RFC 7505): domain refuses mail"
		}
		return []signals.Feature{
			{Name: featureSTARTTLS, Status: signals.StatusAbsent, Confidence: 0.95, Reasons: []string{reason}},
			{Name: featureDANE, Status: signals.StatusAbsent, Confidence: 0.95, Reasons: []string{reason}},
		}
	}

	conc := p.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}

	hosts := uniqueMXHosts(mxRes.Records)

	// Fan out per-host SMTP probes.
	mxResults := make([]MXProbeResult, len(hosts))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(conc)
	for i, h := range hosts {
		g.Go(func() error {
			mxResults[i] = p.Dialer.Probe(gctx, h, p.Port, p.OurName)
			return nil
		})
	}
	_ = g.Wait()

	// Fan out per-host TLSA lookups in parallel with PKIX checks.
	tlsaResults := make([]dnsclient.TLSAResult, len(hosts))
	tlsaErrs := make([]error, len(hosts))
	pkixOK := make([]bool, len(hosts))
	pkixErr := make([]string, len(hosts))

	g2, gctx2 := errgroup.WithContext(ctx)
	g2.SetLimit(conc)
	for i, h := range hosts {
		g2.Go(func() error {
			res, err := p.DNS.LookupTLSA(gctx2, "_25._tcp."+h)
			tlsaResults[i] = res
			tlsaErrs[i] = err
			ok, errStr := VerifyChain(mxResults[i].PeerCertificates, h)
			pkixOK[i] = ok
			pkixErr[i] = errStr
			return nil
		})
	}
	_ = g2.Wait()

	// Assemble STARTTLS feature.
	startSummaries := make([]MXSummary, len(hosts))
	allAccepted := true
	anyConnect := false
	for i := range hosts {
		mxRes := mxResults[i]
		anyConnect = anyConnect || mxRes.Connected
		s := MXSummary{
			Host:               mxRes.Host,
			STARTTLSAdvertised: mxRes.STARTTLSAdvertised,
			STARTTLSAccepted:   mxRes.STARTTLSAccepted,
			ConnectErr:         mxRes.ConnectErr,
			TLSErr:             mxRes.TLSErr,
			DurationMs:         mxRes.DurationMs,
			PKIXValid:          pkixOK[i],
			PKIXErr:            pkixErr[i],
		}
		if mxRes.STARTTLSAccepted {
			s.TLSVersion = TLSVersionName(mxRes.TLSVersion)
		}
		if len(mxRes.PeerCertificates) > 0 {
			leaf := mxRes.PeerCertificates[0]
			s.LeafSubject = leaf.Subject.String()
			s.LeafIssuer = leaf.Issuer.String()
			s.LeafSANs = leaf.DNSNames
			s.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
			s.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
		if !mxRes.STARTTLSAccepted {
			allAccepted = false
		}
		startSummaries[i] = s
	}

	startStatus := signals.StatusPresent
	startConf := 0.9
	startReasons := []string{}
	if !anyConnect {
		startStatus = signals.StatusUnknown
		startConf = 0.1
		startReasons = append(startReasons, "could not connect to any MX on :25 (firewall or upstream down)")
	} else if !allAccepted {
		startStatus = signals.StatusMisconfigured
		startReasons = append(startReasons, "not every MX supports STARTTLS")
	} else {
		startReasons = append(startReasons, fmt.Sprintf("all %d MX accept STARTTLS", len(hosts)))
	}

	startFeat := signals.Feature{
		Name:       featureSTARTTLS,
		Status:     startStatus,
		Confidence: startConf,
		Reasons:    startReasons,
		Details:    STARTTLSDetails{MXResults: startSummaries},
	}

	// Assemble DANE feature.
	daneResults := make([]DANEMXResult, len(hosts))
	anyTLSA, allMatch := false, true
	for i, h := range hosts {
		d := DANEMXResult{Host: h, Target: "_25._tcp." + h}
		if tlsaErrs[i] != nil {
			d.LookupErr = tlsaErrs[i].Error()
			daneResults[i] = d
			allMatch = false
			continue
		}
		d.NumRecords = len(tlsaResults[i].Records)
		for _, rec := range tlsaResults[i].Records {
			d.Records = append(d.Records, TLSAEntry{
				Usage:        rec.Usage,
				Selector:     rec.Selector,
				MatchingType: rec.MatchingType,
			})
		}
		if d.NumRecords == 0 {
			daneResults[i] = d
			allMatch = false
			continue
		}
		anyTLSA = true
		matchedIdx := matchTLSA(tlsaResults[i].Records, mxResults[i].PeerCertificates)
		if matchedIdx >= 0 {
			d.Matched = true
			rec := tlsaResults[i].Records[matchedIdx]
			d.MatchedRR = fmt.Sprintf("%d %d %d", rec.Usage, rec.Selector, rec.MatchingType)
		} else {
			allMatch = false
		}
		daneResults[i] = d
	}

	daneStatus := signals.StatusAbsent
	daneConf := 0.9
	daneReasons := []string{}
	switch {
	case !anyTLSA:
		daneReasons = append(daneReasons, "no TLSA records at any _25._tcp.<mx>")
	case anyTLSA && allMatch:
		daneStatus = signals.StatusPresent
		daneConf = 0.95
		daneReasons = append(daneReasons, "all MX with TLSA match the presented certificate")
	default:
		daneStatus = signals.StatusMisconfigured
		daneConf = 0.9
		daneReasons = append(daneReasons, "TLSA published but does not match presented certificate at some MX")
	}

	daneFeat := signals.Feature{
		Name:       featureDANE,
		Status:     daneStatus,
		Confidence: daneConf,
		Reasons:    daneReasons,
		Details:    DANEDetails{MXResults: daneResults},
	}

	return []signals.Feature{startFeat, daneFeat}
}

// matchTLSA returns the index of the TLSA record that matches the
// leaf certificate, or -1 if none matches. We only consider the leaf;
// trust-anchor verification (Usage 0/2) is not modelled here.
func matchTLSA(records []dnsclient.TLSARecord, chain []*x509.Certificate) int {
	if len(chain) == 0 {
		return -1
	}
	leaf := chain[0]
	for i, rec := range records {
		var source []byte
		switch rec.Selector {
		case 0: // Full cert
			source = leaf.Raw
		case 1: // SubjectPublicKeyInfo
			source = leaf.RawSubjectPublicKeyInfo
		default:
			continue
		}
		var digest []byte
		switch rec.MatchingType {
		case 0: // exact bytes
			digest = source
		case 1: // SHA-256
			h := sha256.Sum256(source)
			digest = h[:]
		case 2: // SHA-512
			h := sha512.Sum512(source)
			digest = h[:]
		default:
			continue
		}
		if bytesEqual(digest, rec.Data) {
			return i
		}
	}
	return -1
}

func bytesEqual(a, b []byte) bool {
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

func uniqueMXHosts(records []dnsclient.MX) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, m := range records {
		h := strings.TrimSuffix(strings.ToLower(m.Host), ".")
		if h == "" || h == "." {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

func isNullMX(records []dnsclient.MX) bool {
	if len(records) != 1 {
		return false
	}
	r := records[0]
	return r.Preference == 0 && (r.Host == "" || r.Host == ".")
}
