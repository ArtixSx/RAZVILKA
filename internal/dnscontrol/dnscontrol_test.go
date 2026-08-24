package dnscontrol

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDraftPersistsWithoutChangingApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetDraft("ad-block"); err != nil {
		t.Fatal(err)
	}
	snapshot := m.Snapshot()
	if !snapshot.Dirty || snapshot.Draft.ProfileID != "ad-block" || snapshot.Applied.ProfileID != "automatic" || snapshot.Mode != "preview" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot().Draft.ProfileID != "ad-block" {
		t.Fatal("draft did not persist")
	}
}

func TestRejectsUnknownProfile(t *testing.T) {
	m, _ := New("")
	if err := m.SetDraft("unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, err := m.Probe(context.Background(), "unknown"); err == nil {
		t.Fatal("unknown profile probe accepted")
	}
}

func TestCatalogHasUsefulProfiles(t *testing.T) {
	wanted := map[string]bool{"ad-block": false, "family": false, "security": false, "private": false}
	for _, profile := range Profiles() {
		if _, ok := wanted[profile.ID]; ok {
			wanted[profile.ID] = true
		}
	}
	for id, found := range wanted {
		if !found {
			t.Fatalf("missing profile %s", id)
		}
	}
}

func TestPlanRefusesToReplaceExistingRouterDNS(t *testing.T) {
	m, _ := New("")
	if err := m.SetDraft("ad-block"); err != nil {
		t.Fatal(err)
	}
	plan := m.Plan("Keenetic ndnproxy: udp :53")
	if plan.Ready || plan.Listener == "" || len(plan.Steps) < 6 {
		t.Fatalf("unsafe DNS plan = %+v", plan)
	}
	foundOwnership := false
	for _, check := range plan.Checks {
		if check.ID == "ownership" && check.Status == "fail" {
			foundOwnership = true
		}
	}
	if !foundOwnership {
		t.Fatalf("ownership gate missing: %+v", plan.Checks)
	}
}

func TestAutomaticDNSPlanRequiresNoLiveChange(t *testing.T) {
	m, _ := New("")
	plan := m.Plan("Keenetic ndnproxy: udp :53")
	if !plan.Ready || plan.Profile.ID != "automatic" {
		t.Fatalf("automatic plan = %+v", plan)
	}
}
