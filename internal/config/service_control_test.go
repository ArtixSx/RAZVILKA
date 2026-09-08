package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestServiceControlScheduleModePersistAndCASWithoutApplying(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("telegram", ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	mode := "manual"
	schedule := ServiceCheckSchedule{Enabled: true, IntervalSeconds: 300, ServiceIDs: []string{"telegram"}}
	if err := s.UpdateServiceControl(&mode, &schedule, before.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateServiceControl(&mode, nil, before.Revision); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale control saved", err)
	}
	schedule.ServiceIDs[0] = "changed"
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.Get()
	if got.ServiceControl.EffectiveMode() != "manual" || got.ServiceControl.Schedule.ServiceIDs[0] != "telegram" || !reflect.DeepEqual(got.Services, before.Services) || !reflect.DeepEqual(got.AppliedServices, before.AppliedServices) || got.AppliedRevision != before.AppliedRevision {
		t.Fatal("settings applied or failed persistence")
	}
	copy := s.Get()
	copy.ServiceControl.Schedule.ServiceIDs[0] = "mutated"
	if s.Get().ServiceControl.Schedule.ServiceIDs[0] != "telegram" {
		t.Fatal("Get aliases schedule")
	}
}

func TestServiceControlRuntimeCyclePreservesExactPendingAndDisabledChoices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, _ := Load(path)
	_ = s.SetSafeMode(false)
	_ = s.UpdateService("telegram", ServiceState{Enabled: true, Route: "sing-box:node-fixture", Sources: []string{"192.168.1.40/32"}})
	_ = s.UpdateService("youtube", ServiceState{Enabled: false, Route: "usque", Sources: []string{"192.168.1.41/32"}})
	_ = s.ApplyDraft()
	_ = s.UpdateService("telegram", ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.42/32"}})
	before := s.Get()
	undo, err := s.CommitServiceRuntime(true, map[string]string{"telegram": "sing-box:node-fixture"}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	stopped := s.Get()
	if !stopped.ServiceControl.Stopped || len(stopped.AppliedServices) != 0 || !reflect.DeepEqual(stopped.Services, before.Services) || !reflect.DeepEqual(stopped.ServiceControl.SuspendedServices, before.AppliedServices) {
		t.Fatal("stop discarded pending or disabled selections")
	}
	if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("stop rollback failed", err)
	}
	_, err = s.CommitServiceRuntime(true, map[string]string{"telegram": "sing-box:node-fixture"}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	s, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resumeUndo, err := s.CommitServiceRuntime(false, nil, s.Get().Revision)
	if err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	if after.ServiceControl.Stopped || !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || !reflect.DeepEqual(after.Services, before.Services) || len(after.ServiceControl.SuspendedRoutes) != 0 {
		t.Fatal("resume changed desired or previous scope")
	}
	if err := resumeUndo(); err != nil || !s.Get().ServiceControl.Stopped {
		t.Fatal("resume rollback failed", err)
	}
}

func TestServiceControlRejectsInvalidOrUnconfiguredMutation(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "config.json"))
	_ = s.SetSafeMode(false)
	before := s.Get()
	for _, schedule := range []ServiceCheckSchedule{{Enabled: true, IntervalSeconds: 1, ServiceIDs: []string{"telegram"}}, {Enabled: true, IntervalSeconds: 60}, {Enabled: true, IntervalSeconds: 60, ServiceIDs: []string{"telegram", "telegram"}}} {
		if err := s.UpdateServiceControl(nil, &schedule, before.Revision); err == nil {
			t.Fatal("invalid schedule accepted")
		}
	}
	if _, err := s.CommitServiceRuntime(true, nil, before.Revision); err == nil {
		t.Fatal("unconfigured stop invented resume snapshot")
	}
	if !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("rejected control changed config")
	}
}
