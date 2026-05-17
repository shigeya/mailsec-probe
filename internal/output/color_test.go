package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

func TestColorizer_ModeNever_NoEscapes(t *testing.T) {
	c := NewColorizer(ColorNever, &bytes.Buffer{})
	if got := c.Status(signals.StatusPresent); strings.Contains(got, "\033[") {
		t.Fatalf("Never should produce no ANSI escapes, got %q", got)
	}
	if c.Enabled() {
		t.Fatal("Never -> Enabled should be false")
	}
}

func TestColorizer_ModeAlways_ContainsEscapes(t *testing.T) {
	c := NewColorizer(ColorAlways, &bytes.Buffer{})
	got := c.Status(signals.StatusPresent)
	if !strings.Contains(got, "\033[32m") || !strings.HasSuffix(got, "\033[0m") {
		t.Fatalf("Always should wrap in green + reset, got %q", got)
	}
}

func TestColorizer_AutoOnBuffer_IsOff(t *testing.T) {
	// Auto on a non-TTY writer (a bytes.Buffer) should be off.
	c := NewColorizer(ColorAuto, &bytes.Buffer{})
	if c.Enabled() {
		t.Fatal("Auto on a buffer should be off")
	}
}

func TestColorizer_StatusPaletteByLevel(t *testing.T) {
	c := NewColorizer(ColorAlways, &bytes.Buffer{})
	cases := []struct {
		s    signals.Status
		want string
	}{
		{signals.StatusPresent, "\033[32m"},
		{signals.StatusMisconfigured, "\033[33m"},
		{signals.StatusUnknown, "\033[31m"},
		{signals.StatusAbsent, "\033[90m"},
	}
	for _, tc := range cases {
		if got := c.Status(tc.s); !strings.Contains(got, tc.want) {
			t.Errorf("Status(%s) = %q, want substring %q", tc.s, got, tc.want)
		}
	}
}

func TestWriteHumanColored_AlignsColumnsRegardlessOfColor(t *testing.T) {
	reports := []signals.Report{{
		Domain: "example.com",
		Features: []signals.Feature{
			{Name: "spf", Status: signals.StatusPresent, Confidence: 0.95},
			{Name: "dmarc", Status: signals.StatusMisconfigured, Confidence: 0.95},
		},
	}}
	var plain, coloured bytes.Buffer
	if err := WriteHumanColored(&plain, reports, NewColorizer(ColorNever, &plain)); err != nil {
		t.Fatal(err)
	}
	if err := WriteHumanColored(&coloured, reports, NewColorizer(ColorAlways, &coloured)); err != nil {
		t.Fatal(err)
	}
	// Visible widths after stripping ANSI should be identical.
	if stripANSI(coloured.String()) != plain.String() {
		t.Fatalf("colour-stripped output differs.\nplain:\n%s\nstripped:\n%s", plain.String(), stripANSI(coloured.String()))
	}
}

func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// Skip until the terminating letter (uppercase or lowercase).
			j := i + 2
			for j < len(s) && !((s[j] >= '@' && s[j] <= '~') && s[j] != '[') {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
	}
	return out.String()
}
