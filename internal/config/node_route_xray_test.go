package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestXrayNodeRouteCommitReloadAndGuardedUndo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	node := "node-" + strings.Repeat("a", 64)
	p := DefaultServicePolicy("telegram", ServiceState{})
	p.Enabled, p.Mode, p.AllowedNodeIDs = true, "auto", []string{node}
	if _, err = s.UpdateServicePolicy(p, s.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	for _, bad := range []string{"Xray:" + node, "xray:" + node + " ", "xray:node-a", "xray:group-" + strings.Repeat("a", 32), "xray:home"} {
		if _, err = s.ApplyNodeRouteWithRollback("telegram", bad, before.Revision); err == nil || !reflect.DeepEqual(before, s.Get()) {
			t.Fatal("noncanonical route wrote config", bad)
		}
	}
	if _, err = s.ApplyNodeRouteWithRollback("telegram", "xray:"+node, before.Revision+1); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale CAS accepted", err)
	}
	undo, err := s.ApplyNodeRouteScopeWithRollback("telegram", "xray:"+node, []string{"192.168.1.40"}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	after := reloaded.Get()
	if after.AppliedServices["telegram"].Route != "xray:"+node || after.ServicePolicies["telegram"].PinnedNodeID != node || after.ServicePolicies["telegram"].Enabled || after.Revision != before.Revision+1 {
		t.Fatal("engine or policy fence lost", after)
	}
	if err = undo(); err != nil || !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("Xray scope rollback changed unrelated authority", err)
	}
}
