package output

import (
	"io"
	"os"

	"github.com/shigeya/mailsec-probe/internal/signals"
)

// ColorMode controls whether ANSI escapes are emitted.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"   // colorize when stdout is a TTY and NO_COLOR is unset
	ColorAlways ColorMode = "always" // always colorize
	ColorNever  ColorMode = "never"  // never colorize
)

// ANSI escape codes. Kept inline rather than pulled from a dependency
// because the surface is tiny and we want zero new deps for this.
const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"

	ansiGreen  = "\033[32m" // present
	ansiYellow = "\033[33m" // misconfigured
	ansiRed    = "\033[31m" // unknown
	ansiGray   = "\033[90m" // absent
)

// Colorizer wraps strings in ANSI escapes when enabled is true.
//
// When enabled is false, every method is a passthrough — callers can
// always use the Colorizer without branching.
type Colorizer struct {
	enabled bool
}

// NewColorizer resolves mode against the supplied writer. Use os.Stdout
// for runtime; tests pass a stub that pretends to be (or not be) a TTY.
func NewColorizer(mode ColorMode, w io.Writer) Colorizer {
	switch mode {
	case ColorAlways:
		return Colorizer{enabled: true}
	case ColorNever:
		return Colorizer{enabled: false}
	default: // ColorAuto and any unknown value
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			return Colorizer{enabled: false}
		}
		return Colorizer{enabled: isTerminal(w)}
	}
}

// Enabled reports whether color is on.
func (c Colorizer) Enabled() bool { return c.enabled }

// Status wraps a Status value in its conventional colour.
func (c Colorizer) Status(s signals.Status) string {
	return c.colorByStatus(s, string(s))
}

// colorByStatus is the underlying helper: it wraps an arbitrary
// display text in the colour associated with the supplied Status
// value. Use this when you want to render e.g. an uppercase form of
// the status word while still keeping the colour mapping.
func (c Colorizer) colorByStatus(s signals.Status, text string) string {
	if !c.enabled {
		return text
	}
	switch s {
	case signals.StatusPresent:
		return ansiGreen + ansiBold + text + ansiReset
	case signals.StatusMisconfigured:
		return ansiYellow + ansiBold + text + ansiReset
	case signals.StatusUnknown:
		return ansiRed + ansiBold + text + ansiReset
	case signals.StatusAbsent:
		return ansiGray + text + ansiReset
	}
	return text
}

// Dim returns s dimmed (used for confidence and reasons when colour is on).
func (c Colorizer) Dim(s string) string {
	if !c.enabled {
		return s
	}
	return ansiGray + s + ansiReset
}

// isTerminal reports whether w is a *os.File pointing at a character
// device (i.e. probably a terminal). Anything else (pipes, files,
// buffers) returns false.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
