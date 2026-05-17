package output

import (
	"encoding/json"
	"io"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// WriteJSON emits the reports as indented JSON.
//
// Default shape:
//   - one report → encoded as a single object (no array)
//   - many reports → encoded as an array
//
// When withStats is true, the output is always an object
// {"reports": [...], "stats": {...}} so that consumers can pick up
// the cross-domain summary alongside the per-domain payloads.
func WriteJSON(w io.Writer, reports []signals.Report, withStats bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if withStats {
		return enc.Encode(struct {
			Reports []signals.Report `json:"reports"`
			Stats   Stats            `json:"stats"`
		}{
			Reports: reports,
			Stats:   Compute(reports),
		})
	}
	if len(reports) == 1 {
		return enc.Encode(reports[0])
	}
	return enc.Encode(reports)
}
