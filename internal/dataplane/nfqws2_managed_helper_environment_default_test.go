//go:build !linux || !razvilka_native_fixture || !race

package dataplane

import (
	"testing"
)

func TestNFQWSManagedHelperEnvironmentOrdinaryUnchanged(t *testing.T) {
	t.Setenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT", "0")
	t.Setenv("GORACE", "exitcode=0 halt_on_error=1")
	original := []string{"PATH=/original", "LANG=C", "TZ=UTC"}
	got, err := nfqws2ManagedHelperEnvironment(original)
	if err != nil || len(got) != len(original) || &got[0] != &original[0] {
		t.Fatal("ordinary helper environment changed")
	}
}
