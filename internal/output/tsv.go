package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// WriteTSV emits one row per (domain, feature). Columns:
//
//	domain  feature  status  confidence  reason
//
// The header row is always emitted. Tab characters and newlines inside
// reason strings are replaced with spaces so the output stays valid TSV.
func WriteTSV(w io.Writer, reports []signals.Report) error {
	if _, err := fmt.Fprintln(w, "domain\tfeature\tstatus\tconfidence\treason"); err != nil {
		return err
	}
	for _, r := range reports {
		for _, f := range r.Features {
			reason := ""
			if len(f.Reasons) > 0 {
				reason = sanitiseTSV(f.Reasons[0])
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%s\n",
				r.Domain, f.Name, f.Status, f.Confidence, reason); err != nil {
				return err
			}
		}
		for _, e := range r.Errors {
			if _, err := fmt.Fprintf(w, "%s\t!error\t-\t-\t%s\n", r.Domain, sanitiseTSV(e)); err != nil {
				return err
			}
		}
	}
	return nil
}

// sanitiseTSV replaces tab and newline characters with single spaces.
func sanitiseTSV(s string) string {
	r := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")
	return r.Replace(s)
}
