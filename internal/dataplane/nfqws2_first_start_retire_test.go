package dataplane

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func (f *firstStartFixture) assertRetired(t *testing.T) {
	t.Helper()
	if lease, err := f.a.readLease(); err != nil || lease != nil {
		t.Fatal("retirement intent not cleared", err)
	}
	if f.running || f.ownedRules {
		t.Fatal("retired runtime remains")
	}
	if string(f.original[f.a.ConfigPath]) != readText(t, f.a.ConfigPath) {
		t.Fatal("stock main was not returned")
	}
	if _, err := engineconfig.NFQWSFirstStartInitOwner(readBytes(t, f.a.InitPath)); err != nil {
		t.Fatal("retirement re-enabled broad stock startup", err)
	}
	for _, path := range f.a.ownedListPaths() {
		if strings.Contains(readText(t, path), managedBegin) {
			t.Fatal("retired owner list block remains")
		}
	}
}

func TestNFQWS2FirstStartExplicitRemovalKeepsInertAndFreshOwnerCanApply(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	oldOwner, _ := f.a.owner()
	init := readText(t, f.a.InitPath)
	if err := f.a.Deactivate(withNFQWS2Removal(firstStartContext(t))); err != nil {
		t.Fatal(err)
	}
	f.assertRetired(t)
	if readText(t, f.a.InitPath) != init {
		t.Fatal("retirement changed the inert script")
	}
	next := *f.a
	next.StateRoot = ""
	next.stockNativeOwner = nil
	next.firstStartReview = nil
	m := New("/opt/razvilka/fresh-dataplane")
	if err := m.Register(&next); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureNFQWSStockNative(f.owner); err != nil {
		t.Fatal(err)
	}
	f.a, f.m = &next, m
	f.plan.PlanID = "dp-fresh-owner"
	f.apply(t)
	newOwner, _ := f.a.owner()
	if oldOwner == newOwner {
		t.Fatal("fresh state retained removed owner")
	}
	if owner, err := engineconfig.NFQWSFirstStartInitOwner(readBytes(t, f.a.InitPath)); err != nil || owner != newOwner {
		t.Fatal("new exact owner not installed", err)
	}
}

func TestNFQWS2FirstStartRetirementCASRetryPreservesForeignOutsideBlock(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	target := f.a.ownedListPaths()[0]
	injected := false
	f.a.firstStartRetirementReady = func(path string) {
		if path == target && !injected {
			injected = true
			writeStockText(t, path, "foreign.example\n"+readText(t, path))
		}
	}
	if err := f.a.Deactivate(withNFQWS2Removal(firstStartContext(t))); err == nil {
		t.Fatal("foreign edit was overwritten")
	}
	lease, err := f.a.readLease()
	if err != nil || lease == nil || lease.FirstStart.Phase != nfqws2FirstRetiring {
		t.Fatal("partial retirement fence lost", err)
	}
	f.a.firstStartRetirementReady = nil
	if err := f.a.Deactivate(withNFQWS2Removal(firstStartContext(t))); err != nil {
		t.Fatal("exact removal retry failed", err)
	}
	f.assertRetired(t)
	if !strings.HasPrefix(readText(t, target), "foreign.example\n") {
		t.Fatal("foreign list content was lost")
	}
}

func TestNFQWS2FirstStartRemovalIntentDoesNotRelinquishForeignConfig(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+"# external edit\n")
	start := len(f.calls)
	before := readText(t, f.a.ConfigPath)
	if err := f.a.Deactivate(withNFQWS2Removal(firstStartContext(t))); err == nil {
		t.Fatal("foreign config was relinquished")
	}
	for _, call := range f.calls[start:] {
		if firstStartRuntimeAction(call) {
			t.Fatal("foreign config entered a runtime action")
		}
	}
	if before != readText(t, f.a.ConfigPath) {
		t.Fatal("foreign bytes changed")
	}
}

func TestNFQWS2FirstStartPreservedSettingsRetirementNeedsReviewedApply(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	if err := f.a.Deactivate(withNFQWS2Removal(firstStartContext(t))); err != nil {
		t.Fatal(err)
	}
	old, exists, err := f.m.Committed()
	if err != nil || !exists {
		t.Fatal(err)
	}
	allowed := true
	start := len(f.calls)
	if _, err := f.m.Recover(f.bootContext(t, &allowed)); err == nil {
		t.Fatal("removed ownership was silently replayed")
	}
	for _, call := range f.calls[start:] {
		if firstStartRuntimeAction(call) {
			t.Fatal("preserved journal regained retired authority")
		}
	}
	// Desired/applied settings and the historical journal remain untouched.
	// An explicit new reviewed transaction, not journal deletion/reset, installs
	// a fresh exact lease from stock data plus the known inert script.
	f.plan.PlanID = "dp-preserved-settings-reapply"
	f.plan.Digest = strings.Repeat("c", 64)
	f.apply(t)
	current, exists, err := f.m.Committed()
	if err != nil || !exists || current.PlanID == old.PlanID || !f.running {
		t.Fatal("reviewed settings could not be reapplied", err)
	}
}
