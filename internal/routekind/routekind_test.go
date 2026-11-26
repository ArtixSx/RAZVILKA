package routekind

import "testing"

func TestRegistryMembership(t *testing.T) {
	ids := PreferredIDs()
	if len(ids) != PreferredCount {
		t.Fatal(ids)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !IsExecutor(id) || seen[id] {
			t.Fatalf("invalid or duplicate ID %q", id)
		}
		seen[id] = true
	}
}
func TestRegistryRejectsNonCanonicalIDs(t *testing.T) {
	for _, id := range []string{"", "auto", "direct", "Xray", " xray", "xray ", "xray:home", "sing-box:node-1", "wg", "unknown", "xray\x00"} {
		if IsExecutor(id) {
			t.Fatalf("accepted %q", id)
		}
	}
}
func TestRegistryCannotBeMutatedThroughCopy(t *testing.T) {
	a := PreferredIDs()
	a[0] = "foreign"
	if PreferredIDs()[0] != "nfqws2" || IsExecutor("foreign") {
		t.Fatal("registry was mutated")
	}
}
