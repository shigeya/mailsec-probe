// Package txttag parses tag=value style TXT records used by DMARC,
// DKIM, BIMI, TLS-RPT, and MTA-STS.
//
// Format (per RFC 6376 §3.2 and friends):
//
//	tag = value (";" tag = value)*
//
// Whitespace around tag, "=", and value is ignored. Tag matching is
// case-sensitive (matches the RFCs); values are returned verbatim.
package txttag

import "strings"

// Parse splits "v=DMARC1; p=reject; rua=mailto:a@b" into an ordered
// list of (tag, value) pairs. Tags appearing multiple times are
// preserved in input order; callers decide whether to merge or keep
// only the first.
type Pair struct {
	Tag, Value string
}

// Parse returns the tag/value pairs in input order.
func Parse(s string) []Pair {
	out := []Pair{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, value, ok := strings.Cut(part, "=")
		if !ok {
			out = append(out, Pair{Tag: part})
			continue
		}
		out = append(out, Pair{
			Tag:   strings.TrimSpace(tag),
			Value: strings.TrimSpace(value),
		})
	}
	return out
}

// Get returns the first value for tag, or "" if not present.
func Get(pairs []Pair, tag string) string {
	for _, p := range pairs {
		if p.Tag == tag {
			return p.Value
		}
	}
	return ""
}

// Has reports whether tag is present (with or without a value).
func Has(pairs []Pair, tag string) bool {
	for _, p := range pairs {
		if p.Tag == tag {
			return true
		}
	}
	return false
}

// PickByVersion scans txtRecords and returns the first record whose
// first tag is "v" with the given version value (case-insensitive).
// Returns the matching record and its parsed pairs.
//
// "v=DMARC1; p=reject" with version "DMARC1" matches.
// "v=spf1 include:_spf.example.com" with version "DMARC1" does not.
func PickByVersion(txtRecords []string, version string) (raw string, pairs []Pair, ok bool) {
	for _, rec := range txtRecords {
		trimmed := strings.TrimSpace(rec)
		if trimmed == "" {
			continue
		}
		ps := Parse(trimmed)
		if len(ps) == 0 {
			continue
		}
		first := ps[0]
		if strings.EqualFold(first.Tag, "v") && strings.EqualFold(first.Value, version) {
			return rec, ps, true
		}
	}
	return "", nil, false
}
