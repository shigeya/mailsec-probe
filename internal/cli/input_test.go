package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDomainsFile_BasicAndComments(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "domains.txt")
	body := "# header\n\nexample.com\n\n  example.org  \n# trailing comment\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readDomainsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "example.org"}
	if !equalStringSlices(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadDomainsFile_EmptyPath(t *testing.T) {
	got, err := readDomainsFile("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty path should yield no domains, got %#v", got)
	}
}

func TestReadDomainsFile_NotFound(t *testing.T) {
	_, err := readDomainsFile("/no/such/file/here/very/unlikely")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestMergeDomains_DedupAndNormalise(t *testing.T) {
	a := []string{"Example.COM", "  google.com  "}
	b := []string{"example.com", "example.org", ""}
	got := mergeDomains(a, b)
	want := []string{"example.com", "google.com", "example.org"}
	if !equalStringSlices(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
