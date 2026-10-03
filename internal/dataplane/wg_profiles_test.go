package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

func TestNamedWireGuardSnapshotUsesSelectedReserveWithoutMutatingCatalog(t *testing.T) {
	a, _, plan, transaction := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.Background()
	store := wireguardprofile.New(filepath.Join(t.TempDir(), "profiles"))
	a.Profiles = store
	meta, err := store.Put(ctx, "reserve", "Reserve", testOwnWireGuardProfile(""), "")
	if err != nil {
		t.Fatal(err)
	}
	plan.Routes[0].Resolved, plan.Routes[0].Sources = "wireguard:reserve", []string{"192.168.1.4/32"}
	a.Configs = nil // named profiles have no WARP/main file dependency
	if err := a.Snapshot(ctx, plan, transaction); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readWarpWGSnapshot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NamedProfileID != "reserve" || snapshot.ProfilePath != "" || snapshot.NamedProfileRevision != meta.Revision {
		t.Fatal("wrong profile identity")
	}
	if err := a.Stage(ctx, plan, transaction); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(transaction, "rz-warp.conf.staged"))
	if err != nil || !strings.Contains(string(staged), "93.184.216.34:51820") {
		t.Fatal("named endpoint not pinned", err)
	}
	p, err := store.Get(ctx, "reserve")
	if err != nil || !strings.Contains(p.Config(), "vpn.example.com") {
		t.Fatal("catalog hostname changed", err)
	}
	if _, err := store.Put(ctx, "reserve", "New revision", p.Config(), meta.Revision); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate(ctx, plan, transaction); err == nil || !strings.Contains(err.Error(), "changed after snapshot") {
		t.Fatal("stale profile activated", err)
	}
}

func TestWireGuardPlanRejectsConflictingProfiles(t *testing.T) {
	for _, routes := range [][]string{{"wireguard:one", "wireguard:two"}, {"wireguard", "wireguard:one"}, {"wireguard:../escape"}} {
		var plan Plan
		for _, route := range routes {
			plan.Routes = append(plan.Routes, Route{Resolved: route})
		}
		if _, err := selectedWireGuardProfile(plan); err == nil {
			t.Fatal("conflicting profiles accepted")
		}
	}
}
