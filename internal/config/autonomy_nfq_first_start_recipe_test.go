package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func autonomyNFQRecipeStore(t *testing.T) *Store {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("other", ServiceState{Enabled: true, Route: "usque"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("other", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("discord", ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNFQWSFirstStartRecipe(s.Get().Revision, engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAutonomyNFQFirstStartRecipeAtomicPublicationAndUndo(t *testing.T) {
	s := autonomyNFQRecipeStore(t)
	before := s.Get()
	undo, err := s.ApplyAutonomyNFQFirstStartRouteWithRollback("discord", nil, before.NFQWSFirstStartRecipe, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	if after.Revision != before.Revision+1 || after.AppliedRevision != after.Revision || after.AppliedNFQWSFirstStartRecipe != before.NFQWSFirstStartRecipe || after.NFQWSFirstStartRecipe != before.NFQWSFirstStartRecipe || after.AppliedServices["discord"].Route != "nfqws2" {
		t.Fatal("route and selected recipe were not one publication")
	}
	if !reflect.DeepEqual(after.Services["other"], before.Services["other"]) || !reflect.DeepEqual(after.AppliedServices["other"], before.AppliedServices["other"]) {
		t.Fatal("foreign draft/runtime consumed")
	}
	reopened, err := Load(s.path)
	if err != nil || !reflect.DeepEqual(reopened.Get(), after) {
		t.Fatal("disk publication differs", err)
	}
	if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("recipe/draft undo differs", err)
	}
	if err := undo(); err != nil {
		t.Fatal("original undo is not idempotent", err)
	}
	reopened, err = Load(s.path)
	if err != nil || !reflect.DeepEqual(reopened.Get(), before) {
		t.Fatal("disk undo differs", err)
	}
}

func TestAutonomyNFQFirstStartRecipeRefusesRetainedOrUnreviewedSelection(t *testing.T) {
	for _, mode := range []string{"stale", "empty", "invalid", "different", "applied-recipe", "applied-nfq-mode", "applied-auto", "target-applied", "sources", "draft-sources", "disabled", "foreign-route", "safe", "manual", "stop"} {
		t.Run(mode, func(t *testing.T) {
			s := autonomyNFQRecipeStore(t)
			s.mu.Lock()
			switch mode {
			case "applied-recipe":
				s.cfg.AppliedNFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircular
			case "applied-nfq-mode":
				s.cfg.AppliedServices["retained"] = ServiceState{Enabled: true, Mode: "nfqws2"}
			case "applied-auto":
				s.cfg.AppliedServices["retained"] = ServiceState{Enabled: true, Route: "auto"}
			case "target-applied":
				s.cfg.AppliedServices["discord"] = ServiceState{Enabled: true, Route: "usque"}
			case "draft-sources":
				v := s.cfg.Services["discord"]
				v.Sources = []string{"192.168.1.2/32"}
				s.cfg.Services["discord"] = v
			case "disabled":
				v := s.cfg.Services["discord"]
				v.Enabled = false
				s.cfg.Services["discord"] = v
			case "foreign-route":
				v := s.cfg.Services["discord"]
				v.Route = "usque"
				s.cfg.Services["discord"] = v
			case "safe":
				s.cfg.SafeMode = true
			case "manual":
				s.cfg.ServiceControl.Mode = "manual"
			case "stop":
				s.cfg.ServiceControl.Stopped = true
			}
			before := cloneConfig(s.cfg)
			s.mu.Unlock()
			recipe, revision := before.NFQWSFirstStartRecipe, before.Revision
			var sources []string
			switch mode {
			case "stale":
				revision++
			case "empty":
				recipe = ""
			case "invalid":
				recipe = "unreviewed-args"
			case "different":
				recipe = engineconfig.NFQWSFirstStartStockTLSCircular
			case "sources":
				sources = []string{"192.168.1.2/32"}
			}
			undo, err := s.ApplyAutonomyNFQFirstStartRouteWithRollback("discord", sources, recipe, revision)
			if err == nil || undo != nil || !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("unreviewed recipe publication", err)
			}
		})
	}
}

func TestAutonomyNFQFirstStartRecipeUndoRefusesLaterDesiredChange(t *testing.T) {
	s := autonomyNFQRecipeStore(t)
	before := s.Get()
	undo, err := s.ApplyAutonomyNFQFirstStartRouteWithRollback("discord", nil, before.NFQWSFirstStartRecipe, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNFQWSFirstStartRecipe(s.Get().Revision, engineconfig.NFQWSFirstStartStockTLSCircular); err != nil {
		t.Fatal(err)
	}
	changed := s.Get()
	if err := undo(); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), changed) {
		t.Fatal("undo overwrote later consent", err)
	}
}
