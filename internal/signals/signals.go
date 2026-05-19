// Package signals defines the neutral observation types (Signal) and the
// judged result types (Feature, Report) used across mailsec-probe.
//
// Probes produce Signal values without making judgments. The classifier
// consumes Signals to produce Feature values (present/absent/unknown/
// misconfigured + confidence + structured details).
package signals

import "time"

// Status is the high-level verdict for a Feature.
type Status string

const (
	StatusPresent       Status = "present"
	StatusAbsent        Status = "absent"
	StatusUnknown       Status = "unknown"
	StatusMisconfigured Status = "misconfigured"
	// StatusSkipped indicates the probe was intentionally not run
	// (e.g. via a CLI flag such as --no-dkim). It is neither a
	// successful observation nor a failure — measurement simply did
	// not happen for this feature.
	StatusSkipped Status = "skipped"
)

// Source describes where a Signal came from.
type Source string

const (
	SourceDNSTxt    Source = "dns_txt"
	SourceDNSMX     Source = "dns_mx"
	SourceDNSA      Source = "dns_a"
	SourceDNSDS     Source = "dns_ds"
	SourceHTTPSGet  Source = "https_get"
	SourceComposite Source = "composite"
)

// Signal is a neutral observation. A probe MUST NOT decide whether a
// feature is "good" or "bad"; it only records what was seen.
type Signal struct {
	Source  Source            `json:"source"`
	Target  string            `json:"target"`
	OK      bool              `json:"ok"`
	Records []string          `json:"records,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
	Err     string            `json:"err,omitempty"`
}

// Feature is the judged result for one mail-security feature.
//
// Details is a feature-specific struct. Each probe defines its own
// Details type to keep the JSON output strongly shaped per feature.
type Feature struct {
	Name       string   `json:"name"`
	Status     Status   `json:"status"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons,omitempty"`
	Details    any      `json:"details,omitempty"`
	Signals    []Signal `json:"signals,omitempty"`
}

// Report is the top-level output for one domain.
type Report struct {
	Domain    string    `json:"domain"`
	QueriedAt time.Time `json:"queried_at"`
	Features  []Feature `json:"features"`
	Errors    []string  `json:"errors,omitempty"`
}
