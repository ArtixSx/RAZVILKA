package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func networkCommitFixture(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	s.cfg.NetworkPolicy = allInternetPolicy()
	s.cfg.AppliedNetworkPolicy = CloneNetworkPolicy(s.cfg.NetworkPolicy)
	s.cfg.AppliedNetworkPolicy.Traffic.DefaultRoute = "usque"
	s.cfg.Services["site"] = normalizeState(ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.12/32"}})
	s.cfg.AppliedServices["site"] = normalizeState(ServiceState{Enabled: true, Route: "usque", Sources: []string{"192.168.1.11/32"}})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func networkCommitCandidate(before Config) (*NetworkPolicy, map[string]ServiceState) {
	applied := CloneNetworkPolicy(before.NetworkPolicy)
	applied.Traffic.DefaultRoute = "wireguard"
	return applied, map[string]ServiceState{"site": {Enabled: true, Route: "wireguard", Sources: []string{"192.168.1.12/32"}}}
}

func TestNetworkPolicyCommitPreservesEditorAndUndoRestoresExactImage(t *testing.T) {
	s, path := networkCommitFixture(t)
	before := s.Get()
	oldBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	applied, services := networkCommitCandidate(before)
	undo, err := s.CommitNetworkPolicyWithRollback(before, applied, services)
	if err != nil {
		t.Fatal(err)
	}
	committed := s.Get()
	if !reflect.DeepEqual(committed.Services, before.Services) || !reflect.DeepEqual(committed.NetworkPolicy, before.NetworkPolicy) || !reflect.DeepEqual(committed.ServiceControl, before.ServiceControl) {
		t.Fatal("applied commit changed the editor or runtime control")
	}
	if committed.Revision != before.Revision+1 || committed.AppliedRevision != committed.Revision || committed.LastAppliedAt == "" || committed.AppliedNetworkPolicy.Traffic.DefaultRoute != "wireguard" || committed.AppliedServices["site"].Route != "wireguard" {
		t.Fatal("applied identity/revision was not published", committed)
	}
	applied.Clients.SegmentIDs[0] = "mutated"
	services["site"].Sources[0] = "192.168.1.99/32"
	if !reflect.DeepEqual(s.Get(), committed) {
		t.Fatal("input slices escaped into committed state")
	}
	reloaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(reloaded.Get(), committed) {
		t.Fatal("commit did not survive reload", err)
	}
	if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("undo failed", err)
	}
	afterBytes, err := os.ReadFile(path)
	if err != nil || string(afterBytes) != string(oldBytes) {
		t.Fatal("undo did not restore exact file image", err)
	}
	if err := undo(); err != nil {
		t.Fatal("successful undo not idempotent", err)
	}
}

func TestNetworkPolicyCommitDetectsSameRevisionLegacyApply(t *testing.T) {
	s, _ := networkCommitFixture(t)
	before := s.Get()
	applied, services := networkCommitCandidate(before)
	if _, err := s.ApplyDraftScopeWithRollback(DraftScopeServices); err != nil {
		t.Fatal(err)
	}
	current := s.Get()
	if current.Revision != before.Revision || reflect.DeepEqual(current.AppliedServices, before.AppliedServices) {
		t.Fatal("fixture did not exercise a same-revision edit")
	}
	if _, err := s.CommitNetworkPolicyWithRollback(before, applied, services); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), current) {
		t.Fatal("same-revision preimage change accepted", err)
	}
}

func TestNetworkPolicyCommitAndUndoRefuseExternalDiskReplacement(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-commit", true: "before-undo"}[afterCommit], func(t *testing.T) {
			s, path := networkCommitFixture(t)
			before := s.Get()
			applied, services := networkCommitCandidate(before)
			var undo func() error
			if afterCommit {
				var err error
				undo, err = s.CommitNetworkPolicyWithRollback(before, applied, services)
				if err != nil {
					t.Fatal(err)
				}
			}
			memory := s.Get()
			external, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			external = append(external, '\n') // Semantically equal still changes the exact preimage.
			if err := os.WriteFile(path, external, 0600); err != nil {
				t.Fatal(err)
			}
			if afterCommit {
				err = undo()
			} else {
				_, err = s.CommitNetworkPolicyWithRollback(before, applied, services)
			}
			if err == nil || !reflect.DeepEqual(s.Get(), memory) {
				t.Fatal("external replacement accepted or memory changed", err)
			}
			actual, readErr := os.ReadFile(path)
			if readErr != nil || string(actual) != string(external) {
				t.Fatal("foreign file overwritten", readErr)
			}
		})
	}
}

func TestNetworkPolicyCommitLateUndoPreservesNewEditor(t *testing.T) {
	s, _ := networkCommitFixture(t)
	before := s.Get()
	applied, services := networkCommitCandidate(before)
	undo, err := s.CommitNetworkPolicyWithRollback(before, applied, services)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("other", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	current := s.Get()
	if err := undo(); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), current) {
		t.Fatal("late undo overwrote new editor", err)
	}
}

func TestNetworkPolicyCommitRefusesStoppedSafeOverflowAndChangedPolicy(t *testing.T) {
	for _, kind := range []string{"stopped", "safe", "overflow", "changed-policy", "unresolved-auto", "noncanonical-source"} {
		t.Run(kind, func(t *testing.T) {
			s, path := networkCommitFixture(t)
			switch kind {
			case "stopped":
				s.cfg.ServiceControl.Stopped = true
			case "safe":
				s.cfg.SafeMode = true
			case "overflow":
				s.cfg.Revision = ^uint64(0)
			}
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			before := s.Get()
			data, _ := os.ReadFile(path)
			applied, services := networkCommitCandidate(before)
			switch kind {
			case "changed-policy":
				applied.Clients.SegmentIDs = []string{"different"}
			case "unresolved-auto":
				applied.Traffic.DefaultRoute = DefaultRouteAuto
			case "noncanonical-source":
				services["site"] = ServiceState{Enabled: true, Route: "wireguard", Sources: []string{"192.168.1.12"}}
			}
			if _, err := s.CommitNetworkPolicyWithRollback(before, applied, services); err == nil || !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("invalid commit changed memory", err)
			}
			actual, _ := os.ReadFile(path)
			if string(actual) != string(data) {
				t.Fatal("invalid commit changed the file")
			}
		})
	}
}
