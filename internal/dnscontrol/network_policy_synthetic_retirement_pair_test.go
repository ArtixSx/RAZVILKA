package dnscontrol

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Both opaque views come from the real factory and retained source/ledger.
// Resolver transport/publication are the existing explicit fixture models;
// this does not fabricate a dataplane process or grant native cleanup.
func TestSyntheticDNSRetirementIndependentOriginalViews(t *testing.T) {
	f, source, mapping, first, held, _ := syntheticDNSRetirementModel(t)
	second, err := mapping.ReviewRetirement(held, source, f.r.defaultDNS.manager, f.r.frozenPlan, f.control, f.root, f.definition)
	if err != nil {
		t.Fatal("second original review", err)
	}
	if first == second {
		t.Fatal("independent factories unexpectedly returned one wrapper")
	}
	if first.mapping != second.mapping || first.source != second.source || first.control != second.control || first.root != second.root || !os.SameFile(first.anchor, second.anchor) {
		t.Fatal("independent reviews did not retain the same originals")
	}
	for _, view := range []*SyntheticDNSRetirementReview{first, second} {
		if _, err := view.ObserveClosed(held); err == nil {
			t.Fatal("live source became closed evidence")
		}
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	left, err := first.ObserveClosed(held)
	if err != nil {
		t.Fatal("first original closed view", err)
	}
	right, err := second.ObserveClosed(held)
	if err != nil || left.PossiblyIssued || right.PossiblyIssued || !reflect.DeepEqual(left, right) {
		t.Fatal("independent original views disagree", err)
	}
	if err := mapping.Current(held); err == nil {
		t.Fatal("closed views revived forward mapping")
	}
	// Neither view may substitute remembered rows for the real durable ledger.
	if err := os.WriteFile(filepath.Join(f.root, syntheticDNSLedgerName), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, view := range []*SyntheticDNSRetirementReview{first, second} {
		if _, err := view.ObserveClosed(held); err == nil {
			t.Fatal("foreign ledger accepted by original view")
		}
	}
}
