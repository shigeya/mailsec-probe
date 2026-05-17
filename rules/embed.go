// Package rules holds YAML rule files embedded into the binary.
package rules

import _ "embed"

// DKIMSelectorsYAML is the default DKIM selector list bundled into the
// binary. The caller may override it with --dkim-selectors-file.
//
//go:embed dkim_selectors.yaml
var DKIMSelectorsYAML []byte

// DKIMSelectorInferenceYAML maps SPF include patterns to additional
// DKIM selectors. See docs/DKIM_SELECTORS.md.
//
//go:embed dkim_selector_inference.yaml
var DKIMSelectorInferenceYAML []byte
