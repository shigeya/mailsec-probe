package dkim

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shigeya/mailsec-probe/internal/probe/dnsclient"
	"github.com/shigeya/mailsec-probe/rules"
)

// InferenceRule maps a recognised SPF include/redirect target to a list
// of DKIM selectors that the provider is known to use.
type InferenceRule struct {
	MatchInclude string   `yaml:"match_include"`
	AddSelectors []string `yaml:"add_selectors"`
}

// LoadInferenceRules parses the inference YAML. data may be nil to use
// the embedded default.
func LoadInferenceRules(data []byte) ([]InferenceRule, error) {
	if len(data) == 0 {
		data = rules.DKIMSelectorInferenceYAML
	}
	var doc struct {
		Rules []InferenceRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse dkim inference yaml: %w", err)
	}
	return doc.Rules, nil
}

// inferSelectorsFromSPF performs a one-shot TXT lookup at the apex and
// returns the union of selectors implied by any matching include/
// redirect token in the SPF record. Returns an empty slice if no SPF
// is present or no rule fires.
//
// Network failures are swallowed; inference is a best-effort hint, not
// a hard requirement. We never raise the DKIM verdict to "unknown"
// just because inference could not complete.
func inferSelectorsFromSPF(ctx context.Context, dc dnsclient.Client, domain string, irules []InferenceRule) []string {
	if len(irules) == 0 {
		return nil
	}
	res, err := dc.LookupTXT(ctx, domain)
	if err != nil || len(res.Records) == 0 {
		return nil
	}

	var spfRecord string
	for _, r := range res.Records {
		t := strings.TrimSpace(r)
		if len(t) < 6 {
			continue
		}
		if strings.EqualFold(t[:6], "v=spf1") && (len(t) == 6 || t[6] == ' ' || t[6] == '\t') {
			spfRecord = t
			break
		}
	}
	if spfRecord == "" {
		return nil
	}

	// Collect include: and redirect= targets in lower case so the
	// substring match below is stable.
	var targets []string
	for tok := range strings.FieldsSeq(spfRecord) {
		lower := strings.ToLower(tok)
		switch {
		case strings.HasPrefix(lower, "include:"):
			targets = append(targets, lower[len("include:"):])
		case strings.HasPrefix(lower, "redirect="):
			targets = append(targets, lower[len("redirect="):])
		}
	}
	if len(targets) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	var add []string
	for _, rule := range irules {
		needle := strings.ToLower(rule.MatchInclude)
		matched := false
		for _, t := range targets {
			if strings.Contains(t, needle) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, s := range rule.AddSelectors {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			add = append(add, s)
		}
	}
	return add
}

