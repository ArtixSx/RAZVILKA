package dataplane

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

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// These tests use the real builder, empty Manager.Apply and on-disk metadata.
// The inactivity callback is an explicit private model; no native process,
// firewall cleanup, production source binding or router acceptance is claimed.
type emptyStopPublicationModel struct {
	m               *Manager
	prior, target   Plan
	original, final map[string]restorejournal.Image
	execution       Execution
	ctx             context.Context
	root            *ownedfs.Root
}

func newEmptyStopPublicationModel(t *testing.T) emptyStopPublicationModel {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(path)
	when := time.Now().UTC().Add(-2 * time.Second)
	prior, err := BuildAt(Input{Revision: 40,
		Routes:  []Route{{ServiceID: "video", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"video.example"}}},
		Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, when)
	if err != nil || !prior.Ready {
		t.Fatal("prior builder scope unavailable", err)
	}
	prior.State = "committed"
	if !NFQWS2OfflineStopPlanScope(prior) {
		t.Fatal("fixture is outside explicit NFQ Stop scope")
	}
	if err := m.Record(prior); err != nil {
		t.Fatal(err)
	}
	prior, exists, err := m.Committed()
	if err != nil || !exists {
		t.Fatal("retained prior plan unavailable", err)
	}
	oldRoot := filepath.Join(path, "transactions", prior.PlanID)
	if err := m.prepareExecutionRoot(oldRoot); err != nil {
		t.Fatal(err)
	}
	oldExecution := Execution{PlanID: prior.PlanID, Digest: prior.Digest, State: "committed", StartedAt: when.Format(time.RFC3339Nano), FinishedAt: when.Add(time.Second).Format(time.RFC3339Nano), Steps: []ExecutionStep{}}
	if err := m.writeExecution(oldRoot, oldExecution); err != nil {
		t.Fatal(err)
	}
	target, err := BuildAt(Input{Revision: 41}, when.Add(time.Second))
	if err != nil || ValidateNFQWS2EmptyStopPlan(target) != nil {
		t.Fatal("normal empty target unavailable", err)
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f := emptyStopPublicationModel{m: m, prior: prior, target: target, root: root, ctx: ctx}
	f.original = f.read(t)
	f.execution, err = m.Apply(ctx, target, nil)
	if err != nil || f.execution.State != "committed" || len(f.execution.Steps) != 0 || len(f.execution.Resources) != 0 {
		t.Fatal("actual empty Apply failed", err)
	}
	f.final = f.read(t)
	return f
}

func (f emptyStopPublicationModel) read(t *testing.T) map[string]restorejournal.Image {
	t.Helper()
	images := map[string]restorejournal.Image{}
	for _, name := range emptyStopNames(f.target) {
		image, err := readEmptyStopImage(f.root, name)
		if err != nil {
			t.Fatal(err)
		}
		images[name] = image
	}
	return images
}

func (f emptyStopPublicationModel) write(t *testing.T, images map[string]restorejournal.Image) {
	t.Helper()
	for _, name := range emptyStopNames(f.target) {
		image := images[name]
		path := filepath.Join(f.m.StateRoot, name)
		if image.Exists {
			if err := os.WriteFile(path, image.Data, 0600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func emptyStopExecutionImage(t *testing.T, execution Execution) restorejournal.Image {
	t.Helper()
	raw, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return restorejournal.Image{Exists: true, Data: raw}
}

func (f emptyStopPublicationModel) interrupted(t *testing.T, transactionState, latestState string, latestPlan, bootPlan bool) map[string]restorejournal.Image {
	t.Helper()
	images := map[string]restorejournal.Image{}
	for name, image := range f.original {
		images[name] = image
	}
	for i, state := range []string{transactionState, latestState} {
		name := []string{filepath.Join("transactions", f.target.PlanID, "execution.json"), "latest-execution.json"}[i]
		if state == "original" {
			continue
		}
		execution := f.execution
		execution.State = state
		if state != "committed" {
			execution.FinishedAt = ""
		}
		images[name] = emptyStopExecutionImage(t, execution)
	}
	if latestPlan {
		images["latest-plan.json"] = f.final["latest-plan.json"]
	}
	if bootPlan {
		images["latest-committed-plan.json"] = f.final["latest-committed-plan.json"]
	}
	return images
}

func TestNFQWS2EmptyStopPublicationCompletesOnlyOwnEmptyApply(t *testing.T) {
	for _, c := range []struct {
		name, transaction, latest string
		latestPlan, bootPlan      bool
	}{
		{"first-transaction-only", "applying", "original", false, false},
		{"first-latest-only", "original", "applying", false, false},
		{"committing-transaction-first", "committing", "applying", false, false},
		{"committing-latest-first", "applying", "committing", false, false},
		{"partial-plan-publication", "committing", "committing", true, false},
		{"committed-transaction-first", "committed", "committing", true, true},
		{"committed-latest-first", "committing", "committed", true, true},
		{"already-published", "committed", "committed", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newEmptyStopPublicationModel(t)
			images := f.interrupted(t, c.transaction, c.latest, c.latestPlan, c.bootPlan)
			f.write(t, images)
			observations := 0
			inactive := func(ctx context.Context) error { observations++; return ctx.Err() }
			publication, err := f.m.reviewNFQWS2EmptyStopPublication(f.ctx, f.prior, f.target, f.original, inactive)
			if err != nil || !reflect.DeepEqual(publication.Before, images) {
				t.Fatal("review lost exact interrupted images", err)
			}
			ctx := WithReviewGuard(f.ctx, func(c context.Context) error { return c.Err() })
			if err := f.m.completeNFQWS2EmptyStopPublication(ctx, f.prior, f.target, f.original, publication, inactive); err != nil {
				t.Fatal("exact empty continuation failed", err)
			}
			if !reflect.DeepEqual(f.read(t), publication.After) || observations < 2 || f.m.CheckExecutionRecovery(f.ctx) != nil {
				t.Fatal("continuation did not publish agreeing, settled metadata with fresh model observations")
			}
		})
	}
}

func TestNFQWS2EmptyStopPublicationTargetSurvivesJournalRoundtrip(t *testing.T) {
	target, err := BuildAt(Input{Revision: 41}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	var retained Plan
	if err := json.Unmarshal(raw, &retained); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNFQWS2EmptyStopPlan(retained); err != nil {
		t.Fatal("normal empty target cannot resume after outer journal reload", err)
	}
}

func TestNFQWS2EmptyStopPublicationRefusesUnknownExecution(t *testing.T) {
	for _, mode := range []string{"not-entered", "unknown-field", "step", "resource", "resource-plan", "rollback", "conflicting-terminal"} {
		t.Run(mode, func(t *testing.T) {
			f := newEmptyStopPublicationModel(t)
			images := f.interrupted(t, "committed", "committed", true, true)
			x := f.execution
			switch mode {
			case "not-entered":
				images = f.interrupted(t, "original", "original", false, false)
			case "unknown-field":
				raw := images["latest-execution.json"].Data
				images["latest-execution.json"] = restorejournal.Image{Exists: true, Data: append(append([]byte{}, raw[:len(raw)-2]...), []byte(",\n  \"unreviewed_effect\": true\n}")...)}
			case "step":
				x.Steps = []ExecutionStep{{Adapter: "nfqws2", Phase: "activate", State: "passed", FinishedAt: x.FinishedAt}}
			case "resource":
				x.Resources = []ExecutionResource{{}}
			case "resource-plan":
				x.ResourcePlanID = f.prior.PlanID
			case "rollback":
				x.State, x.Error = "rollback-failed", "unsettled execution"
			case "conflicting-terminal":
				finished, err := time.Parse(time.RFC3339Nano, x.FinishedAt)
				if err != nil {
					t.Fatal(err)
				}
				x.FinishedAt = finished.Add(time.Second).Format(time.RFC3339Nano)
			}
			if mode != "not-entered" && mode != "unknown-field" {
				images["latest-execution.json"] = emptyStopExecutionImage(t, x)
			}
			f.write(t, images)
			_, err := f.m.reviewNFQWS2EmptyStopPublication(f.ctx, f.prior, f.target, f.original, func(c context.Context) error { return c.Err() })
			if err == nil || !reflect.DeepEqual(f.read(t), images) {
				t.Fatal("unknown execution was completed or its evidence rewritten", err)
			}
		})
	}
}

func TestNFQWS2EmptyStopPublicationRefusesChangedBytesAndAbsentSource(t *testing.T) {
	f := newEmptyStopPublicationModel(t)
	f.write(t, f.interrupted(t, "committing", "committing", false, false))
	inactive := func(c context.Context) error { return c.Err() }
	publication, err := f.m.reviewNFQWS2EmptyStopPublication(f.ctx, f.prior, f.target, f.original, inactive)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.CompleteNFQWS2EmptyStopPublication(f.ctx, nil, f.prior, f.target, f.original, publication); err == nil {
		t.Fatal("comparison images substituted for an original runtime source")
	}
	changed := f.read(t)
	image := changed["latest-plan.json"]
	image.Data = append(bytes.Clone(image.Data), '\n')
	changed["latest-plan.json"] = image
	f.write(t, changed)
	ctx := WithReviewGuard(f.ctx, inactive)
	if err := f.m.completeNFQWS2EmptyStopPublication(ctx, f.prior, f.target, f.original, publication, inactive); err == nil || !reflect.DeepEqual(f.read(t), changed) {
		t.Fatal("continuation overwrote a changed exact preimage", err)
	}
}

func TestNFQWS2EmptyStopPublicationRequiresLiveFiniteGuardedContext(t *testing.T) {
	for _, mode := range []string{"nil", "unbounded", "canceled", "expired", "no-guard"} {
		t.Run(mode, func(t *testing.T) {
			f := newEmptyStopPublicationModel(t)
			f.write(t, f.interrupted(t, "committing", "committing", false, false))
			inactive := func(c context.Context) error { return c.Err() }
			publication, err := f.m.reviewNFQWS2EmptyStopPublication(f.ctx, f.prior, f.target, f.original, inactive)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithReviewGuard(f.ctx, inactive)
			switch mode {
			case "nil":
				ctx = nil
			case "unbounded":
				ctx = WithReviewGuard(context.Background(), inactive)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "no-guard":
				ctx = f.ctx
			}
			before := f.read(t)
			if err := f.m.completeNFQWS2EmptyStopPublication(ctx, f.prior, f.target, f.original, publication, inactive); err == nil || !reflect.DeepEqual(f.read(t), before) {
				t.Fatal("invalid context admitted continuation writes", err)
			}
		})
	}
}
