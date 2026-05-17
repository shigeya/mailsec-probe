package output

import (
	"encoding/json"
	"io"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// WriteJSON emits a single report (or array of reports) as indented JSON.
func WriteJSON(w io.Writer, reports []signals.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(reports) == 1 {
		return enc.Encode(reports[0])
	}
	return enc.Encode(reports)
}
