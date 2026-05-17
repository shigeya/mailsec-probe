package dnsclient

import (
	"context"
	"fmt"
	"strings"
)

// Mock is a deterministic Client for tests. Populate the maps directly.
//
// The map key for TXT/MX is the lower-cased FQDN without a trailing dot,
// e.g. "example.com", "_dmarc.example.com", "google._domainkey.example.com".
type Mock struct {
	TXT map[string]TXTResult
	MX  map[string]MXResult
	DS  map[string]bool

	// TXTErr / MXErr / DSErr let a test simulate transport-level failures.
	TXTErr map[string]error
	MXErr  map[string]error
	DSErr  map[string]error
}

// NewMock returns a Mock with all maps initialized.
func NewMock() *Mock {
	return &Mock{
		TXT:    map[string]TXTResult{},
		MX:     map[string]MXResult{},
		DS:     map[string]bool{},
		TXTErr: map[string]error{},
		MXErr:  map[string]error{},
		DSErr:  map[string]error{},
	}
}

func (m *Mock) key(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func (m *Mock) LookupTXT(_ context.Context, name string) (TXTResult, error) {
	k := m.key(name)
	if err, ok := m.TXTErr[k]; ok {
		return TXTResult{}, err
	}
	if r, ok := m.TXT[k]; ok {
		return r, nil
	}
	// NXDOMAIN-equivalent: empty answer, RCode 3 (NXDomain).
	return TXTResult{RCode: 3}, nil
}

func (m *Mock) LookupMX(_ context.Context, name string) (MXResult, error) {
	k := m.key(name)
	if err, ok := m.MXErr[k]; ok {
		return MXResult{}, err
	}
	if r, ok := m.MX[k]; ok {
		return r, nil
	}
	return MXResult{RCode: 3}, nil
}

func (m *Mock) HasDS(_ context.Context, name string) (bool, error) {
	k := m.key(name)
	if err, ok := m.DSErr[k]; ok {
		return false, err
	}
	return m.DS[k], nil
}

// Verify Mock satisfies Client at compile time.
var _ Client = (*Mock)(nil)

// String dumps the configured state, useful when debugging tests.
func (m *Mock) String() string {
	var b strings.Builder
	for k, v := range m.TXT {
		fmt.Fprintf(&b, "TXT %s: %v\n", k, v.Records)
	}
	for k, v := range m.MX {
		fmt.Fprintf(&b, "MX %s: %v\n", k, v.Records)
	}
	return b.String()
}
