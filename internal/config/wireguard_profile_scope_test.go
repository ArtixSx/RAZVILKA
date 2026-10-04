package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWireGuardBindingMovesWithScopedRouteApplyAndDiscard(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, pair := range []struct{ oldRoute, oldRevision, newRoute, newRevision string }{
		{"wireguard:backup", a, "direct", ""},
		{"direct", "", "wireguard:backup", b},
		{"wireguard:backup", a, "wireguard:backup", b},
		{"wireguard:backup", a, "wireguard:other", b},
	} {
		for _, discard := range []bool{false, true} {
			s, err := Load(filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			old := ServiceState{Enabled: true, Route: pair.oldRoute, WireGuardProfileRevision: pair.oldRevision, Sources: []string{"192.168.1.40/32"}}
			if err := s.UpdateService("telegram", old); err != nil {
				t.Fatal(err)
			}
			if err := s.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			before := s.Get()
			next := ServiceState{Enabled: true, Route: pair.newRoute, WireGuardProfileRevision: pair.newRevision, Sources: []string{"192.168.1.41/32"}}
			if err := s.UpdateService("telegram", next); err != nil {
				t.Fatal(err)
			}
			if !s.DirtyScope(DraftScopeServices) {
				t.Fatal("profile-only route change hidden", pair)
			}
			if discard {
				if err := s.DiscardDraftScope(DraftScopeServices); err != nil {
					t.Fatal(err)
				}
				got := s.Get().Services["telegram"]
				if got.Route != pair.oldRoute || got.WireGuardProfileRevision != pair.oldRevision || !reflect.DeepEqual(got.Sources, next.Sources) {
					t.Fatal("discard split route/profile or changed device draft", pair)
				}
				if s.DirtyScope(DraftScopeServices) {
					t.Fatal("discard retained profile dirty state")
				}
			} else {
				if _, err := s.ApplyDraftScopeWithRollback(DraftScopeServices); err != nil {
					t.Fatal(err)
				}
				got := s.Get().AppliedServices["telegram"]
				if got.Route != pair.newRoute || got.WireGuardProfileRevision != pair.newRevision || !reflect.DeepEqual(got.Sources, before.AppliedServices["telegram"].Sources) {
					t.Fatal("apply split route/profile or applied device draft", pair)
				}
			}
			if _, err := Load(s.path); err != nil {
				t.Fatal("scope persisted invalid binding", err)
			}
		}
	}
}

func TestWireGuardBindingSurvivesDeviceScopeAndNodeOrAutonomyUndo(t *testing.T) {
	for _, route := range []string{"sing-box:node-" + strings.Repeat("a", 64), "xray:node-" + strings.Repeat("b", 64), "usque"} {
		s, err := Load(filepath.Join(t.TempDir(), "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetSafeMode(false); err != nil {
			t.Fatal(err)
		}
		old := ServiceState{Enabled: true, Route: "wireguard:backup", WireGuardProfileRevision: strings.Repeat("a", 64), Sources: []string{"192.168.1.40/32"}}
		if err := s.UpdateService("telegram", old); err != nil {
			t.Fatal(err)
		}
		if err := s.ApplyDraft(); err != nil {
			t.Fatal(err)
		}
		draft := old
		draft.WireGuardProfileRevision, draft.Sources = strings.Repeat("b", 64), []string{"192.168.1.41/32"}
		if err := s.UpdateService("telegram", draft); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ApplyDraftScopeWithRollback(DraftScopeDevices); err != nil {
			t.Fatal(err)
		}
		if s.Get().AppliedServices["telegram"].WireGuardProfileRevision != old.WireGuardProfileRevision || s.Get().Services["telegram"].WireGuardProfileRevision != draft.WireGuardProfileRevision {
			t.Fatal("device apply changed routing binding")
		}
		if err := s.DiscardDraftScope(DraftScopeDevices); err != nil {
			t.Fatal(err)
		}
		if s.Get().Services["telegram"].WireGuardProfileRevision != draft.WireGuardProfileRevision {
			t.Fatal("device discard changed routing binding")
		}
		before := s.Get()
		var undo func() error
		if route == "usque" {
			undo, err = s.ApplyAutonomyRouteWithRollback("telegram", route, []string{"192.168.1.40"}, before.Revision)
		} else {
			undo, err = s.ApplyNodeRouteWithRollback("telegram", route, before.Revision)
		}
		if err != nil {
			t.Fatal("non-WG route retained profile binding", route, err)
		}
		for _, state := range []ServiceState{s.Get().Services["telegram"], s.Get().AppliedServices["telegram"]} {
			if state.Route != route || state.WireGuardProfileRevision != "" {
				t.Fatal("old named binding survived different executor")
			}
		}
		if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
			t.Fatal("undo did not restore exact named binding", err)
		}
	}
}
