package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNodeRouteCommitRevisionAndGuardedUndo(t *testing.T) {
	store, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	route := "sing-box:node-" + strings.Repeat("a", 64)
	if _, err := store.ApplyNodeRouteWithRollback("telegram", route, before.Revision+1); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("stale revision changed config")
	}
	undo, err := store.ApplyNodeRouteWithRollback("telegram", route, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(); err != nil || !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("targeted commit did not undo")
	}
	if err := undo(); err != nil {
		t.Fatal("undo is not idempotent")
	}
	undo, err = store.ApplyNodeRouteWithRollback("telegram", route, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", ServiceState{Route: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	changed := store.Get()
	if err := undo(); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(changed, store.Get()) {
		t.Fatal("undo overwrote a concurrent setting")
	}
}

func TestNodeRouteExplicitScopeCommitsAndRollsBackOneServiceAtomically(t *testing.T) {
	store, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", ServiceState{Sources: []string{"192.168.1.2"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", ServiceState{Sources: []string{"192.168.1.3"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", ServiceState{Enabled: true, Route: "usque"}); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	route := "sing-box:node-" + strings.Repeat("a", 64)
	if _, err := store.ApplyNodeRouteScopeWithRollback("telegram", route, []string{"127.0.0.1"}, before.Revision); err == nil || !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("invalid explicit source changed configuration")
	}
	sources := []string{"192.168.1.40", "192.168.1.40/32"}
	undo, err := store.ApplyNodeRouteScopeWithRollback("telegram", route, sources, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	sources[0] = "192.168.1.99"
	after := store.Get()
	if !reflect.DeepEqual(after.AppliedServices["telegram"].Sources, []string{"192.168.1.40/32"}) || !reflect.DeepEqual(after.Services["telegram"].Sources, after.AppliedServices["telegram"].Sources) || after.Services["telegram"].Route != route || !reflect.DeepEqual(after.Services["youtube"], before.Services["youtube"]) || after.Revision != before.Revision+1 {
		t.Fatal("explicit scope was not an isolated atomic commit")
	}
	if err := undo(); err != nil || !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("undo did not restore both applied and pending device scope")
	}
	if _, err := store.ApplyNodeRouteScopeWithRollback("telegram", route, nil, before.Revision); err != nil || len(store.Get().AppliedServices["telegram"].Sources) != 0 || len(store.Get().Services["telegram"].Sources) != 0 {
		t.Fatal("explicit all-LAN selection retained a previous device scope")
	}
}

func TestNodeExplicitScopeFencesPolicyAndRemainsReloadableAtScopeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	nodeID := "node-" + strings.Repeat("a", 64)
	policy := DefaultServicePolicy("telegram", ServiceState{})
	policy.Enabled, policy.Mode, policy.AllowedNodeIDs = true, "auto", []string{nodeID}
	if _, err := store.UpdateServicePolicy(policy, store.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	sources := make([]string, 128)
	for i := range sources {
		sources[i] = fmt.Sprintf("192.168.2.%d/32", i+1)
	}
	undo, err := store.ApplyNodeRouteScopeWithRollback("telegram", "sing-box:"+nodeID, sources, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("manual policy fence made configuration unreadable: %v", err)
	}
	p := reloaded.Get().ServicePolicies["telegram"]
	if p.Enabled || p.Mode != "manual" || p.Revision != before.ServicePolicies["telegram"].Revision+1 || len(p.DeviceSources) != 128 || p.PinnedNodeID != nodeID || !reflect.DeepEqual(p.AllowedNodeIDs, policy.AllowedNodeIDs) {
		t.Fatal("manual commit did not retain trust bounds while fencing automatic authority")
	}
	if err := undo(); err != nil || !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("rollback failed to restore prior policy authority with its device scope")
	}
}
