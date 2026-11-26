package startuptools

import "testing"

func TestReviewedCounterProtocolUsesExactVersion(t *testing.T) {
	for version, want := range map[string]string{"1.8.10 (legacy)": "6", "1.8.11 (legacy)": "tcp", "1.4.21": "tcp", "1.8.10": "", "1.8.10 (nf_tables)": "", "1.8.12 (legacy)": "", "": ""} {
		if got := reviewedCounterProtocol(version); got != want {
			t.Fatal(version, got, want)
		}
	}
}
