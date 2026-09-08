package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAutonomyCommitIsScopedAndUndoGuarded(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateService("other", ServiceState{Enabled: true, Route: "usque", Sources: []string{"192.168.1.11"}}); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateService("other", ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.12"}}); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	route := "sing-box:node-" + strings.Repeat("a", 64)
	undo, err := s.ApplyAutonomyRouteWithRollback("custom-site", route, []string{"192.168.1.50"}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if !reflect.DeepEqual(got.Services["other"], before.Services["other"]) || !reflect.DeepEqual(got.AppliedServices["other"], before.AppliedServices["other"]) {
		t.Fatal("unrelated draft or runtime changed")
	}
	if got.AppliedServices["custom-site"].Route != route || !reflect.DeepEqual(got.AppliedServices["custom-site"].Sources, []string{"192.168.1.50/32"}) {
		t.Fatal("scope lost")
	}
	if err = undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("rollback failed", err)
	}
	if err = undo(); err != nil {
		t.Fatal("undo not idempotent")
	}
	_, err = s.ApplyAutonomyRouteWithRollback("custom-site", route, nil, before.Revision+1)
	if !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale consent accepted")
	}
}
func TestAutonomyCommitHonorsSafeModeAndManualMode(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	if _, err = s.ApplyAutonomyRouteWithRollback("site", "nfqws2", nil, before.Revision); err == nil || !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("Safe Mode bypassed")
	}
	if err = s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	mode := "manual"
	if err = s.UpdateServiceControl(&mode, nil, s.Get().Revision); err != nil {
		t.Fatal(err)
	}
	before = s.Get()
	if _, err = s.ApplyAutonomyRouteWithRollback("site", "nfqws2", nil, before.Revision); err == nil || !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("manual mode bypassed")
	}
}
func TestAutonomyRemovalRetainsOtherServices(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"custom-site", "other"} {
		if err = s.UpdateService(id, ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	undo, err := s.ApplyAutonomyRemovalWithRollback("custom-site", true, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	if _, ok := after.Services["custom-site"]; ok {
		t.Fatal("deleted service retained")
	}
	if !reflect.DeepEqual(after.AppliedServices["other"], before.AppliedServices["other"]) {
		t.Fatal("other service removed")
	}
	if err = undo(); err != nil || !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("removal rollback failed", err)
	}
	undo, err = s.ApplyAutonomyRemovalWithRollback("custom-site", false, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get().AppliedServices["custom-site"].Enabled {
		t.Fatal("stop did not stop")
	}
	if err = s.UpdateService("other", ServiceState{Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	changed := s.Get()
	if err = undo(); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(changed, s.Get()) {
		t.Fatal("undo clobbered newer intent")
	}
}
