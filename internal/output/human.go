package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// WriteHuman emits a human-readable summary for each report.
func WriteHuman(w io.Writer, reports []signals.Report) error {
	for idx, rep := range reports {
		if idx > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, rep.Domain)
		for i, f := range rep.Features {
			branch := "├─"
			if i == len(rep.Features)-1 {
				branch = "└─"
			}
			detail := primaryDetail(f)
			fmt.Fprintf(w, "%s %-10s %-13s conf=%.2f   %s\n",
				branch,
				strings.ToUpper(f.Name),
				strings.ToUpper(string(f.Status)),
				f.Confidence,
				detail,
			)
		}
		for _, e := range rep.Errors {
			fmt.Fprintf(w, "! %s\n", e)
		}
	}
	return nil
}

// primaryDetail returns a one-line summary for a Feature row.
func primaryDetail(f signals.Feature) string {
	if len(f.Reasons) > 0 {
		return f.Reasons[0]
	}
	return ""
}
