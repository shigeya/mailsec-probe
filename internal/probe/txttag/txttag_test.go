package txttag

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Pair
	}{
		{
			name: "DMARC typical",
			in:   "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			want: []Pair{
				{"v", "DMARC1"},
				{"p", "reject"},
				{"rua", "mailto:dmarc@example.com"},
			},
		},
		{
			name: "trailing semicolons and whitespace",
			in:   "v=BIMI1 ; l=https://example.com/logo.svg ; ",
			want: []Pair{
				{"v", "BIMI1"},
				{"l", "https://example.com/logo.svg"},
			},
		},
		{
			name: "tag without =",
			in:   "v=DKIM1;k=rsa;t",
			want: []Pair{
				{"v", "DKIM1"},
				{"k", "rsa"},
				{"t", ""}, // tag-only entries get empty value
			},
		},
		{
			name: "empty",
			in:   "",
			want: []Pair{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.in)
			// Normalise tag-only pair: Parse stores Tag-only with Value="" and Tag containing the full token.
			// Above we expect the same: when there's no "=", the whole part becomes Tag and Value stays "".
			// Adjust expectation for "tag without =" case: Tag is "t".
			if tc.name == "tag without =" {
				tc.want[2] = Pair{Tag: "t"}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestPickByVersion(t *testing.T) {
	records := []string{
		"v=spf1 include:_spf.example.com ~all",
		"v=DMARC1; p=reject",
	}
	raw, pairs, ok := PickByVersion(records, "DMARC1")
	if !ok {
		t.Fatal("expected to find DMARC1 record")
	}
	if raw != records[1] {
		t.Fatalf("raw = %q", raw)
	}
	if Get(pairs, "p") != "reject" {
		t.Fatalf("p tag missing: %#v", pairs)
	}

	if _, _, ok := PickByVersion(records, "BIMI1"); ok {
		t.Fatal("should not match BIMI1 in SPF/DMARC records")
	}
}

func TestPickByVersion_caseInsensitiveTagAndValue(t *testing.T) {
	records := []string{"V=dmarc1; p=none"}
	_, _, ok := PickByVersion(records, "DMARC1")
	if !ok {
		t.Fatal("expected case-insensitive match")
	}
}

func TestHasAndGet(t *testing.T) {
	pairs := Parse("v=DKIM1; k=rsa; p=ABCDE")
	if !Has(pairs, "k") {
		t.Fatal("Has(k) should be true")
	}
	if Has(pairs, "t") {
		t.Fatal("Has(t) should be false")
	}
	if Get(pairs, "p") != "ABCDE" {
		t.Fatalf("Get(p) = %q", Get(pairs, "p"))
	}
	if Get(pairs, "missing") != "" {
		t.Fatal("Get(missing) should return empty")
	}
}
