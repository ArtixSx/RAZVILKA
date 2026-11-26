package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func recoveryStopConfigFixture(t *testing.T) (*Store, Config) {
	t.Helper()
	s, e := Load(filepath.Join(t.TempDir(), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	s.SetSafeMode(false)
	s.UpdateService("video", ServiceState{Enabled: true, Route: "nfqws2"})
	s.ApplyDraft()
	s.UpdateService("pending", ServiceState{Enabled: true, Route: "auto"})
	s.SetSafeMode(true)
	return s, s.Get()
}
func TestCommitServiceRecoveryStopAtomicAndUndo(t *testing.T) {
	s, b := recoveryStopConfigFixture(t)
	undo, e := s.CommitServiceRecoveryStop(b, map[string]string{"video": "nfqws2"})
	if e != nil {
		t.Fatal(e)
	}
	a := s.Get()
	if a.SafeMode || !a.ServiceControl.Stopped || len(a.AppliedServices) != 0 || !reflect.DeepEqual(a.Services, b.Services) || a.ServiceControl.SuspendedRoutes["video"] != "nfqws2" {
		t.Fatal("invalid stop")
	}
	if e := undo(); e != nil || !reflect.DeepEqual(s.Get(), b) {
		t.Fatal("full SafeMode/config undo failed", e)
	}
}
func TestCommitServiceRecoveryStopRefusesChangedOrExpandedScope(t *testing.T) {
	for _, mode := range []string{"changed", "mixed", "empty", "not-safe", "already-stopped"} {
		t.Run(mode, func(t *testing.T) {
			s, b := recoveryStopConfigFixture(t)
			routes := map[string]string{"video": "nfqws2"}
			switch mode {
			case "changed":
				s.UpdateService("pending", ServiceState{Route: "direct"})
			case "mixed":
				routes["other"] = "sing-box"
			case "empty":
				routes = map[string]string{}
			case "not-safe":
				s.SetSafeMode(false)
				b = s.Get()
			case "already-stopped":
				b.ServiceControl.Stopped = true
			}
			before := s.Get()
			if _, e := s.CommitServiceRecoveryStop(b, routes); e == nil || !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("unsafe commit")
			}
		})
	}
}

func TestCommitServiceRecoveryStopUndoRefusesConcurrentMutation(t *testing.T) {
	s, b := recoveryStopConfigFixture(t)
	undo, e := s.CommitServiceRecoveryStop(b, map[string]string{"video": "nfqws2"})
	if e != nil {
		t.Fatal(e)
	}
	s.UpdateService("new", ServiceState{Route: "direct"})
	current := s.Get()
	if e = undo(); e == nil || !reflect.DeepEqual(s.Get(), current) {
		t.Fatal("undo overwrote newer user edit")
	}
}
