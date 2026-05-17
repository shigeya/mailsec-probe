package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// Summarizer is implemented by per-probe Details types to provide a
// one-line, human-friendly summary that goes beyond the verdict reason.
// If a Details type does not implement Summarizer, the first reason is
// shown instead.
type Summarizer interface {
	Summary() string
}

// WriteHuman emits a human-readable summary for each report.
func WriteHuman(w io.Writer, reports []signals.Report) error {
	return WriteHumanColored(w, reports, Colorizer{})
}

// WriteHumanColored is WriteHuman with explicit color control.
func WriteHumanColored(w io.Writer, reports []signals.Report, c Colorizer) error {
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
			fmt.Fprintf(w, "%s %-10s %s   %s   %s\n",
				branch,
				strings.ToUpper(f.Name),
				colouredStatusCell(c, f.Status),
				c.Dim(fmt.Sprintf("conf=%.2f", f.Confidence)),
				detail,
			)
		}
		for _, e := range rep.Errors {
			fmt.Fprintf(w, "! %s\n", e)
		}
	}
	return nil
}

// colouredStatusCell renders the status in uppercase coloured by its
// semantic level, then pads to the longest status width (13 chars:
// "MISCONFIGURED") so columns line up even after the invisible ANSI
// escapes are added.
func colouredStatusCell(c Colorizer, s signals.Status) string {
	upper := strings.ToUpper(string(s))
	pad := 13 - len(upper)
	if pad < 0 {
		pad = 0
	}
	return c.colorByStatus(s, upper) + strings.Repeat(" ", pad)
}

// primaryDetail returns a one-line summary for a Feature row. The
// Summarizer interface is preferred; otherwise we fall back to the
// first verdict reason.
func primaryDetail(f signals.Feature) string {
	if s, ok := f.Details.(Summarizer); ok {
		if line := s.Summary(); line != "" {
			if len(f.Reasons) > 0 && f.Status != signals.StatusPresent {
				return f.Reasons[0] + "  |  " + line
			}
			return line
		}
	}
	if len(f.Reasons) > 0 {
		return f.Reasons[0]
	}
	return ""
}
