// Package classifier orchestrates probes against a single domain and
// assembles their Features into a Report.
//
// Probes are run in parallel via errgroup. Probe failures do not abort
// the report; they surface as a Feature with Status=unknown plus a
// reason string. Only top-level errors (e.g. invalid input) end up in
// Report.Errors.
package classifier

import (
	"context"
	"sort"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// Probe runs one feature observation. Implementations must be
// goroutine-safe and must not modify their inputs.
type Probe interface {
	Name() string
	Run(ctx context.Context, domain string) signals.Feature
}

// Runner runs a fixed set of probes against one domain.
type Runner struct {
	probes []Probe
}

// New returns a Runner. The slice ordering is preserved in the output
// so callers can control the human-readable presentation order.
func New(probes ...Probe) *Runner {
	return &Runner{probes: probes}
}

// Probes returns the configured probe list (read-only).
func (r *Runner) Probes() []Probe {
	out := make([]Probe, len(r.probes))
	copy(out, r.probes)
	return out
}

// Run executes every probe in parallel.
func (r *Runner) Run(ctx context.Context, domain string) signals.Report {
	rep := signals.Report{
		Domain:    domain,
		QueriedAt: time.Now().UTC(),
	}
	if domain == "" {
		rep.Errors = append(rep.Errors, "empty domain")
		return rep
	}

	features := make([]signals.Feature, len(r.probes))

	g, gctx := errgroup.WithContext(ctx)
	for i, p := range r.probes {
		g.Go(func() error {
			features[i] = p.Run(gctx, domain)
			return nil
		})
	}
	_ = g.Wait()

	rep.Features = features

	// Stable sort by configured order is already preserved; we sort
	// only when the same probe slot ends up empty (defensive).
	sort.SliceStable(rep.Features, func(i, j int) bool {
		return featureOrder(rep.Features[i].Name) < featureOrder(rep.Features[j].Name)
	})
	return rep
}

// featureOrder gives a canonical display ordering. Unknown features go
// to the end while preserving relative input order.
func featureOrder(name string) int {
	order := map[string]int{
		"spf":     1,
		"dmarc":   2,
		"dkim":    3,
		"mx":      4,
		"mta-sts": 5,
		"tls-rpt": 6,
		"bimi":    7,
		"dnssec":  8,
	}
	if v, ok := order[name]; ok {
		return v
	}
	return 99
}
