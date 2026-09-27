package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestSuspendedDraftBaselineAndScopedDiscard(t *testing.T) {
	for _, scope := range []DraftScope{DraftScopeAll, DraftScopeServices, DraftScopeDevices} {
		t.Run(string(scope), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			s, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			original := ServiceState{Enabled: true, Mode: "direct", Route: "direct", Sources: []string{"192.168.1.40/32"}}
			if err := s.UpdateService("telegram", original); err != nil {
				t.Fatal(err)
			}
			if err := s.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CommitServiceRuntime(true, map[string]string{"telegram": "direct"}, s.Get().Revision); err != nil {
				t.Fatal(err)
			}
			for _, check := range []DraftScope{DraftScopeAll, DraftScopeServices, DraftScopeDevices} {
				if s.DirtyScope(check) {
					t.Fatalf("stop invented changes in %s", check)
				}
			}
			copy := ServiceDraftBaseline(s.Get())
			copy["telegram"].Sources[0] = "192.168.1.99/32"
			if !reflect.DeepEqual(s.Get().ServiceControl.SuspendedServices["telegram"], original) {
				t.Fatal("baseline aliases saved scope")
			}
			edited := ServiceState{Enabled: false, Route: "auto", Sources: []string{"192.168.1.41/32"}}
			if err := s.UpdateService("telegram", edited); err != nil {
				t.Fatal(err)
			}
			for _, check := range []DraftScope{DraftScopeAll, DraftScopeServices, DraftScopeDevices} {
				if !s.DirtyScope(check) {
					t.Fatalf("real changes hidden in %s", check)
				}
			}
			if err := s.DiscardDraftScope(scope); err != nil {
				t.Fatal(err)
			}
			s, err = Load(path)
			if err != nil {
				t.Fatal(err)
			}
			got := s.Get()
			if !got.ServiceControl.Stopped || len(got.AppliedServices) != 0 || !reflect.DeepEqual(got.ServiceControl.SuspendedServices["telegram"], original) {
				t.Fatal("discard resumed or replaced saved routes")
			}
			desired := got.Services["telegram"]
			if scope != DraftScopeDevices && (!desired.Enabled || desired.Route != "direct") {
				t.Fatal("route discard lost saved selection")
			}
			if scope == DraftScopeDevices && (desired.Enabled || desired.Route != "auto") {
				t.Fatal("device discard erased route edit")
			}
			wantSources := original.Sources
			if scope == DraftScopeServices {
				wantSources = edited.Sources
			}
			if !reflect.DeepEqual(desired.Sources, wantSources) {
				t.Fatal("wrong source scope after discard")
			}
			if s.DirtyScope(scope) {
				t.Fatal("discard left phantom changes")
			}
			if scope != DraftScopeAll && !s.Dirty() {
				t.Fatal("discard hid another scope's edit")
			}
			if _, err := s.CommitServiceRuntime(false, nil, got.Revision); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.Get().AppliedServices["telegram"], original) || !reflect.DeepEqual(s.Get().Services, got.Services) {
				t.Fatal("resume changed saved routes or editor")
			}
		})
	}
}
