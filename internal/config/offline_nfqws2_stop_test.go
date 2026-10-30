package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func offlineNFQWS2StopConfig(t *testing.T, safe bool) (*Store, Config, context.Context) {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("video", ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.20/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("video", ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.21/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("pending", ServiceState{Enabled: true, Route: "xray"}); err != nil {
		t.Fatal(err)
	}
	// Preserve a disabled applied selection as well as the enabled Stop scope.
	s.cfg.AppliedServices["paused"] = normalizeState(ServiceState{Route: "direct", Sources: []string{"192.168.1.22/32"}})
	s.cfg.Services["paused"] = normalizeState(ServiceState{Route: "auto"})
	s.cfg.SafeMode = safe
	s.cfg.CatalogPath = "/opt/etc/razvilka/reviewed-catalog.json"
	s.cfg.EngineOrder = []string{"xray", "nfqws2", "sing-box"}
	s.cfg.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto
	s.cfg.AppliedNFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircular
	s.cfg.ServiceControl.Mode = "manual"
	s.cfg.ServiceControl.Schedule = ServiceCheckSchedule{Enabled: true, ServiceIDs: []string{"video"}, IntervalSeconds: 600}
	policy := DefaultServicePolicy("video", s.cfg.AppliedServices["video"])
	policy.Enabled, policy.Mode, policy.Revision = true, "auto", 7
	policy.AllowedEngines = []string{"nfqws2", "xray"}
	s.cfg.ServicePolicies = map[string]ServicePolicy{"video": policy}
	s.cfg.InactiveResourceExclusions = &ResourceExclusions{Schema: 1, Revision: 3, Manual: []ResourceMatch{{Kind: "exact", Value: "private.example"}}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	// Admit the fixture through the same existing-file decoder as the CLI.
	s, err = LoadExisting(s.path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return s, s.Get(), ctx
}

func offlineNFQWS2StopTime() time.Time {
	return time.Date(2026, 10, 30, 12, 34, 56, 987654321, time.FixedZone("reviewed-offset", 3*60*60))
}

func offlineNFQWS2StopBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNFQWS2OfflineStopFrozenImageAndUndo(t *testing.T) {
	for _, safe := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "recovery"}[safe], func(t *testing.T) {
			s, before, ctx := offlineNFQWS2StopConfig(t, safe)
			original := offlineNFQWS2StopBytes(t, s.path)
			resolved := map[string]string{"video": "nfqws2"}
			predicted, err := ReviewedNFQWS2StopImage(before, resolved, offlineNFQWS2StopTime())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, s.Get()) || !bytes.Equal(original, offlineNFQWS2StopBytes(t, s.path)) {
				t.Fatal("image construction changed the original Store")
			}
			undo, err := s.CommitNFQWS2OfflineStop(ctx, before, resolved, offlineNFQWS2StopTime())
			if err != nil || undo == nil {
				t.Fatal("exact Stop publication failed", err)
			}
			after := s.Get()
			wantBytes, err := json.MarshalIndent(predicted, "", "  ")
			if err != nil || !reflect.DeepEqual(after, predicted) || !bytes.Equal(wantBytes, offlineNFQWS2StopBytes(t, s.path)) {
				t.Fatal("pre-recorded image differs from actual durable config", err)
			}
			if after.SafeMode || !after.ServiceControl.Stopped || len(after.AppliedServices) != 0 ||
				after.Revision != before.Revision+1 || after.AppliedRevision != after.Revision || after.LastAppliedAt != "2026-10-30T09:34:56Z" ||
				!reflect.DeepEqual(after.ServiceControl.SuspendedServices, before.AppliedServices) || !reflect.DeepEqual(after.ServiceControl.SuspendedRoutes, resolved) {
				t.Fatal("Stop did not retain the exact applied scope and frozen timestamp")
			}
			// Compare every field after removing only the documented Stop delta.
			unchanged := cloneConfig(after)
			unchanged.SafeMode, unchanged.Revision, unchanged.AppliedRevision, unchanged.LastAppliedAt = before.SafeMode, before.Revision, before.AppliedRevision, before.LastAppliedAt
			unchanged.AppliedServices = cloneServices(before.AppliedServices)
			unchanged.ServiceControl.Stopped = before.ServiceControl.Stopped
			unchanged.ServiceControl.SuspendedServices = before.ServiceControl.SuspendedServices
			unchanged.ServiceControl.SuspendedRoutes = before.ServiceControl.SuspendedRoutes
			if !reflect.DeepEqual(unchanged, before) {
				t.Fatal("Stop consumed a desired edit, policy, recipe, schedule or retained exclusion")
			}
			reloaded, err := LoadExisting(s.path)
			if err != nil || !reflect.DeepEqual(reloaded.Get(), after) {
				t.Fatal("stopped configuration did not survive reload", err)
			}
			if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) || !bytes.Equal(original, offlineNFQWS2StopBytes(t, s.path)) {
				t.Fatal("undo did not restore complete original config and exact bytes", err)
			}
		})
	}
}

func TestNFQWS2OfflineStopDiskCASPreservesExternalSameRevisionBytes(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "undo"}[afterCommit], func(t *testing.T) {
			s, before, ctx := offlineNFQWS2StopConfig(t, true)
			var undo func() error
			var err error
			if afterCommit {
				undo, err = s.CommitNFQWS2OfflineStop(ctx, before, map[string]string{"video": "nfqws2"}, offlineNFQWS2StopTime())
				if err != nil {
					t.Fatal(err)
				}
			}
			memory := s.Get()
			// Even a semantically identical external rewrite is a changed preimage.
			external := append(offlineNFQWS2StopBytes(t, s.path), '\n')
			if err := os.WriteFile(s.path, external, 0600); err != nil {
				t.Fatal(err)
			}
			decoded, _, err := InspectBytes(external)
			if err != nil || !reflect.DeepEqual(decoded, memory) {
				t.Fatal("fixture did not preserve semantic state and revision", err)
			}
			if afterCommit {
				err = undo()
			} else {
				undo, err = s.CommitNFQWS2OfflineStop(ctx, before, map[string]string{"video": "nfqws2"}, offlineNFQWS2StopTime())
				if undo != nil {
					t.Fatal("failed commit returned an undo capability")
				}
			}
			if err == nil || !reflect.DeepEqual(s.Get(), memory) || !bytes.Equal(external, offlineNFQWS2StopBytes(t, s.path)) {
				t.Fatal("Stop or undo overwrote changed disk bytes", err)
			}
		})
	}
}

func TestNFQWS2OfflineStopWholeImageCASAndLateUndo(t *testing.T) {
	t.Run("same-revision-review-drift", func(t *testing.T) {
		s, before, ctx := offlineNFQWS2StopConfig(t, true)
		original := offlineNFQWS2StopBytes(t, s.path)
		expected := cloneConfig(before)
		expected.Services["pending"] = normalizeState(ServiceState{Enabled: true, Route: "direct"})
		undo, err := s.CommitNFQWS2OfflineStop(ctx, expected, map[string]string{"video": "nfqws2"}, offlineNFQWS2StopTime())
		if !errors.Is(err, ErrRevisionChanged) || undo != nil || !reflect.DeepEqual(s.Get(), before) || !bytes.Equal(original, offlineNFQWS2StopBytes(t, s.path)) {
			t.Fatal("same-revision full-image drift was accepted", err)
		}
	})
	t.Run("later-edit-blocks-undo", func(t *testing.T) {
		s, before, ctx := offlineNFQWS2StopConfig(t, true)
		undo, err := s.CommitNFQWS2OfflineStop(ctx, before, map[string]string{"video": "nfqws2"}, offlineNFQWS2StopTime())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateService("new-draft", ServiceState{Route: "direct"}); err != nil {
			t.Fatal(err)
		}
		current, raw := s.Get(), offlineNFQWS2StopBytes(t, s.path)
		if err := undo(); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), current) || !bytes.Equal(raw, offlineNFQWS2StopBytes(t, s.path)) {
			t.Fatal("undo consumed a later desired edit", err)
		}
	})
}

func TestNFQWS2OfflineStopRefusesMalformedScope(t *testing.T) {
	for _, mode := range []string{"empty", "missing", "mixed", "extra", "disabled-route", "no-applied", "already-stopped", "revision-overflow", "zero-time", "invalid-sources", "invalid-schedule"} {
		t.Run(mode, func(t *testing.T) {
			s, before, ctx := offlineNFQWS2StopConfig(t, true)
			resolved, when := map[string]string{"video": "nfqws2"}, offlineNFQWS2StopTime()
			switch mode {
			case "empty":
				resolved = nil
			case "missing":
				resolved = map[string]string{"other": "nfqws2"}
			case "mixed":
				resolved["video"] = "sing-box"
			case "extra":
				resolved["other"] = "nfqws2"
			case "disabled-route":
				resolved["paused"] = "nfqws2"
			case "no-applied":
				before.AppliedServices = map[string]ServiceState{}
				resolved = nil
			case "already-stopped":
				before.ServiceControl.Stopped = true
			case "revision-overflow":
				before.Revision = ^uint64(0)
			case "zero-time":
				when = time.Time{}
			case "invalid-sources":
				state := before.AppliedServices["video"]
				state.Sources = []string{"not-a-client"}
				before.AppliedServices["video"] = state
			case "invalid-schedule":
				before.ServiceControl.Schedule.IntervalSeconds = 1
			}
			original := offlineNFQWS2StopBytes(t, s.path)
			if _, err := ReviewedNFQWS2StopImage(before, resolved, when); err == nil {
				t.Fatal("image constructor accepted unreviewed Stop scope")
			}
			// Model an invalid retained in-memory image without writing it first.
			s.cfg = cloneConfig(before)
			undo, err := s.CommitNFQWS2OfflineStop(ctx, before, resolved, when)
			if err == nil || undo != nil || !reflect.DeepEqual(s.Get(), before) || !bytes.Equal(original, offlineNFQWS2StopBytes(t, s.path)) {
				t.Fatal("invalid Stop changed config or returned an undo capability", err)
			}
		})
	}
}

func TestNFQWS2OfflineStopRequiresLiveFiniteContext(t *testing.T) {
	for _, mode := range []string{"nil", "unbounded", "canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s, before, ctx := offlineNFQWS2StopConfig(t, false)
			switch mode {
			case "nil":
				ctx = nil
			case "unbounded":
				ctx = context.Background()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			original := offlineNFQWS2StopBytes(t, s.path)
			undo, err := s.CommitNFQWS2OfflineStop(ctx, before, map[string]string{"video": "nfqws2"}, offlineNFQWS2StopTime())
			if err == nil || undo != nil || !reflect.DeepEqual(s.Get(), before) || !bytes.Equal(original, offlineNFQWS2StopBytes(t, s.path)) {
				t.Fatal("invalid operation context admitted config publication", err)
			}
		})
	}
}

func TestReviewedNFQWS2StopImageDoesNotAliasInputs(t *testing.T) {
	_, before, _ := offlineNFQWS2StopConfig(t, true)
	resolved := map[string]string{"video": "nfqws2"}
	after, err := ReviewedNFQWS2StopImage(before, resolved, offlineNFQWS2StopTime())
	if err != nil {
		t.Fatal(err)
	}
	expected := cloneConfig(after)
	resolved["video"] = "xray"
	before.AppliedServices["video"].Sources[0] = "192.168.1.99/32"
	before.Services["video"].Sources[0] = "192.168.1.98/32"
	before.ServicePolicies["video"].AllowedEngines[0] = "sing-box"
	before.ServiceControl.Schedule.ServiceIDs[0] = "pending"
	before.InactiveResourceExclusions.Manual[0].Value = "changed.example"
	if !reflect.DeepEqual(after, expected) {
		t.Fatal("mutable input changed the reviewed stopped image")
	}
}

func TestNFQWS2OfflineStopRetainedEmptyMapNeedsFreshExactStoreSnapshot(t *testing.T) {
	s, _, ctx := offlineNFQWS2StopConfig(t, true)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(offlineNFQWS2StopBytes(t, s.path), &document); err != nil {
		t.Fatal(err)
	}
	// Existing files may explicitly retain an empty optional map. A compact
	// outer WAL omits it, while Store must retain its exact decoded snapshot.
	document["service_policies"] = json.RawMessage(`{}`)
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = LoadExisting(s.path)
	if err != nil {
		t.Fatal(err)
	}
	current := s.Get()
	encoded, _ := json.Marshal(current)
	var retained Config
	if err := json.Unmarshal(encoded, &retained); err != nil || reflect.DeepEqual(current, retained) {
		t.Fatal("fixture did not exercise a retained optional-map representation change", err)
	}
	resolved := map[string]string{"video": "nfqws2"}
	if undo, err := s.CommitNFQWS2OfflineStop(ctx, retained, resolved, offlineNFQWS2StopTime()); !errors.Is(err, ErrRevisionChanged) || undo != nil || !bytes.Equal(raw, offlineNFQWS2StopBytes(t, s.path)) {
		t.Fatal("general Store CAS was weakened to accept a detached encoded snapshot", err)
	}
	predicted, err := ReviewedNFQWS2StopImage(retained, resolved, offlineNFQWS2StopTime())
	if err != nil {
		t.Fatal(err)
	}
	// The outer protocol first checks frozen raw bytes and complete encoded
	// equality; only then may it use this Store's actual exact snapshot.
	if _, err := s.CommitNFQWS2OfflineStop(ctx, current, resolved, offlineNFQWS2StopTime()); err != nil {
		t.Fatal(err)
	}
	afterRaw, _ := json.MarshalIndent(predicted, "", "  ")
	if !bytes.Equal(afterRaw, offlineNFQWS2StopBytes(t, s.path)) {
		t.Fatal("fresh exact Store snapshot changed the frozen target bytes")
	}
}
