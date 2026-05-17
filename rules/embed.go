// Package rules holds YAML rule files embedded into the binary.
package rules

import _ "embed"

// DKIMSelectorsYAML is the default DKIM selector list bundled into the
// binary. The caller may override it with --dkim-selectors-file.
//
//go:embed dkim_selectors.yaml
var DKIMSelectorsYAML []byte
