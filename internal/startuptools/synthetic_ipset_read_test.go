package startuptools

import "testing"

func TestSyntheticIPSetSourceCannotBeIssuedByZeroOrClosedLease(t *testing.T) {
	for _, lease := range []*Lease{nil, {}} {
		if source, err := lease.SyntheticBaselineIPSetReader(); source != nil || err == nil {
			t.Fatal("unissued lease created original reader")
		}
	}
}
