package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

func makeReport(domain string, features map[string]signals.Status) signals.Report {
	r := signals.Report{Domain: domain}
	for name, st := range features {
		r.Features = append(r.Features, signals.Feature{Name: name, Status: st, Confidence: 0.9})
	}
	return r
}

func TestCompute_AggregatesByFeature(t *testing.T) {
	reports := []signals.Report{
		makeReport("a", map[string]signals.Status{
			"spf": signals.StatusPresent, "dmarc": signals.StatusPresent, "mta-sts": signals.StatusPresent,
		}),
		makeReport("b", map[string]signals.Status{
			"spf": signals.StatusPresent, "dmarc": signals.StatusAbsent, "mta-sts": signals.StatusAbsent,
		}),
		makeReport("c", map[string]signals.Status{
			"spf": signals.StatusMisconfigured, "dmarc": signals.StatusAbsent, "mta-sts": signals.StatusAbsent,
		}),
	}
	got := Compute(reports)
	if got.NumDomains != 3 {
		t.Fatalf("num_domains = %d", got.NumDomains)
	}

	byName := map[string]FeatureStat{}
	for _, f := range got.Features {
		byName[f.Feature] = f
	}
	if byName["spf"].Present != 2 || byName["spf"].Misconfigured != 1 {
		t.Errorf("spf = %+v", byName["spf"])
	}
	if byName["dmarc"].Present != 1 || byName["dmarc"].Absent != 2 {
		t.Errorf("dmarc = %+v", byName["dmarc"])
	}
	if byName["mta-sts"].Present != 1 || byName["mta-sts"].Absent != 2 {
		t.Errorf("mta-sts = %+v", byName["mta-sts"])
	}
}

func TestCompute_SortsByTotalDescending(t *testing.T) {
	// spf appears in 2 reports, dmarc in 1.
	reports := []signals.Report{
		{Domain: "a", Features: []signals.Feature{
			{Name: "spf", Status: signals.StatusPresent},
			{Name: "dmarc", Status: signals.StatusPresent},
		}},
		{Domain: "b", Features: []signals.Feature{
			{Name: "spf", Status: signals.StatusPresent},
		}},
	}
	got := Compute(reports)
	if got.Features[0].Feature != "spf" {
		t.Fatalf("expected spf first, got %s", got.Features[0].Feature)
	}
}

func TestWriteStatsHuman_HasSummaryHeader(t *testing.T) {
	reports := []signals.Report{
		makeReport("a", map[string]signals.Status{"spf": signals.StatusPresent}),
	}
	var buf bytes.Buffer
	if err := WriteStatsHuman(&buf, reports); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "=== Summary (1 domain) ===") {
		t.Fatalf("missing summary header:\n%s", buf.String())
	}
}

func TestWriteStatsTSV_Format(t *testing.T) {
	reports := []signals.Report{
		makeReport("a", map[string]signals.Status{"spf": signals.StatusPresent}),
		makeReport("b", map[string]signals.Status{"spf": signals.StatusAbsent}),
	}
	var buf bytes.Buffer
	if err := WriteStatsTSV(&buf, reports); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "# stats num_domains=2\n") {
		t.Fatalf("missing stats header: %q", out)
	}
	if !strings.Contains(out, "spf\t2\t1\t1\t0\t0") {
		t.Fatalf("missing spf row: %q", out)
	}
}

func TestWriteTSV_HeaderAndRows(t *testing.T) {
	reports := []signals.Report{{
		Domain: "example.com",
		Features: []signals.Feature{{
			Name: "spf", Status: signals.StatusPresent, Confidence: 0.95,
			Reasons: []string{"qualifier=fail"},
		}},
	}}
	var buf bytes.Buffer
	if err := WriteTSV(&buf, reports); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines: %q", len(lines), buf.String())
	}
	if lines[0] != "domain\tfeature\tstatus\tconfidence\treason" {
		t.Fatalf("header = %q", lines[0])
	}
	if lines[1] != "example.com\tspf\tpresent\t0.95\tqualifier=fail" {
		t.Fatalf("row = %q", lines[1])
	}
}

func TestSanitiseTSV_ReplacesTabsAndNewlines(t *testing.T) {
	got := sanitiseTSV("a\tb\nc\rd")
	if got != "a b c d" {
		t.Fatalf("got %q", got)
	}
}
