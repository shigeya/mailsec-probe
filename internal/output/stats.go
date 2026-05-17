package output

import (
	"fmt"
	"io"
	"sort"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// Stats is the cross-domain aggregation included in --stats output.
type Stats struct {
	NumDomains int           `json:"num_domains"`
	Features   []FeatureStat `json:"features"`
}

// FeatureStat reports per-feature counts of each verdict over all
// domains. Domains that did not produce a given feature (e.g. the
// active probes when --active was off) are excluded from that
// feature's Total.
type FeatureStat struct {
	Feature       string `json:"feature"`
	Total         int    `json:"total"`
	Present       int    `json:"present"`
	Absent        int    `json:"absent"`
	Misconfigured int    `json:"misconfigured"`
	Unknown       int    `json:"unknown"`
}

// PercentPresent returns the fraction of total reports where the
// feature was present, expressed as a 0–100 integer for display.
func (s FeatureStat) PercentPresent() int {
	if s.Total == 0 {
		return 0
	}
	return int((float64(s.Present) * 100) / float64(s.Total))
}

// Compute returns the cross-domain stats for the supplied reports.
func Compute(reports []signals.Report) Stats {
	counts := map[string]*FeatureStat{}
	order := []string{} // preserve first-seen feature order
	for _, r := range reports {
		for _, f := range r.Features {
			c, ok := counts[f.Name]
			if !ok {
				c = &FeatureStat{Feature: f.Name}
				counts[f.Name] = c
				order = append(order, f.Name)
			}
			c.Total++
			switch f.Status {
			case signals.StatusPresent:
				c.Present++
			case signals.StatusAbsent:
				c.Absent++
			case signals.StatusMisconfigured:
				c.Misconfigured++
			case signals.StatusUnknown:
				c.Unknown++
			}
		}
	}
	out := Stats{NumDomains: len(reports)}
	for _, name := range order {
		out.Features = append(out.Features, *counts[name])
	}
	// Stable: by total descending then name. Keeps the most-observed
	// feature at the top of a long list.
	sort.SliceStable(out.Features, func(i, j int) bool {
		if out.Features[i].Total != out.Features[j].Total {
			return out.Features[i].Total > out.Features[j].Total
		}
		return out.Features[i].Feature < out.Features[j].Feature
	})
	return out
}

// WriteStatsHuman writes an ASCII summary table.
func WriteStatsHuman(w io.Writer, reports []signals.Report) error {
	s := Compute(reports)
	fmt.Fprintf(w, "\n=== Summary (%d domain%s) ===\n", s.NumDomains, plural(s.NumDomains))
	fmt.Fprintf(w, "%-10s %-15s %-15s %-15s %-15s\n",
		"feature", "present", "absent", "misconfig", "unknown")
	for _, f := range s.Features {
		fmt.Fprintf(w, "%-10s %-15s %-15s %-15s %-15s\n",
			f.Feature,
			countCell(f.Present, f.Total),
			countCell(f.Absent, f.Total),
			countCell(f.Misconfigured, f.Total),
			countCell(f.Unknown, f.Total),
		)
	}
	return nil
}

// WriteStatsTSV appends stats rows to a TSV stream after a separator
// comment so naive consumers can stop reading at "# stats".
func WriteStatsTSV(w io.Writer, reports []signals.Report) error {
	s := Compute(reports)
	if _, err := fmt.Fprintf(w, "# stats num_domains=%d\n", s.NumDomains); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "feature\ttotal\tpresent\tabsent\tmisconfigured\tunknown"); err != nil {
		return err
	}
	for _, f := range s.Features {
		if _, err := fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\n",
			f.Feature, f.Total, f.Present, f.Absent, f.Misconfigured, f.Unknown); err != nil {
			return err
		}
	}
	return nil
}

func countCell(n, total int) string {
	if n == 0 {
		return "0"
	}
	pct := int((float64(n) * 100) / float64(total))
	return fmt.Sprintf("%d (%d%%)", n, pct)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
