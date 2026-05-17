package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// readDomainsFile parses a domain list file.
//
// Format:
//   - one domain per line
//   - blank lines are ignored
//   - lines starting with "#" are comments (full-line only)
//   - trailing inline "#..." is NOT stripped (a "#" can appear in a
//     domain — though that is exceedingly rare — and stripping it would
//     mask real input errors)
//
// Pass "-" as path to read from stdin.
func readDomainsFile(path string) ([]string, error) {
	var rc io.ReadCloser
	switch path {
	case "":
		return nil, nil
	case "-":
		rc = io.NopCloser(os.Stdin)
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open --input %s: %w", path, err)
		}
		rc = f
	}
	defer rc.Close()

	var out []string
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read --input %s: %w", path, err)
	}
	return out, nil
}

// mergeDomains combines two slices (typically CLI args and --input
// file contents), normalises to lower-case + trimmed, and removes
// duplicates while preserving first-seen order.
func mergeDomains(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, src := range [][]string{a, b} {
		for _, d := range src {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}
