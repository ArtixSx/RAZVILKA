package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func disabledManualCandidateFixture(t *testing.T) (*App, nodeCheckJobRequest) {
	t.Helper()
	a, request := durableNodeFixture(t, 1)
	state := a.Store.Get().Services["telegram"]
	state.Enabled = false
	if err := a.Store.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	revision := a.Store.Get().Revision
	request.ExpectedRevision = &revision
	return a, request
}

func TestManualCandidateDurableDisabledServiceChecksWithoutActivation(t *testing.T) {
	a, request := disabledManualCandidateFixture(t)
	before := a.Store.Get()
	calls := 0
	var original context.Context
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		original = ctx
		if err := a.nodeCandidateResourceAdmission(ctx, before, a.Catalog.Services[0], "another-node", "", netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
			t.Fatal("manual intent granted another candidate", err)
		}
		// A diagnostic context never changes the autonomous enabled gate.
		if err := a.nodeResourceAdmission(ctx, before, a.Catalog.Services[0], "", netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
			t.Fatal("manual intent granted autonomous operation", err)
		}
		return autofallbackResult(r, true), nil
	})
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	if job := durableJobAt(t, a, id); job.State != "completed" || job.Cursor != 1 || calls != 1 {
		t.Fatal("explicit disabled-service candidate was not checked", job, calls)
	}
	view := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if view.Passed != 1 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("diagnostic activated service or lost isolated result", view)
	}
	// Removing cancellation from a copied context does not resurrect the
	// original per-step intent after cleanup and release.
	if err := a.nodeCandidateResourceAdmission(context.WithoutCancel(original), before, a.Catalog.Services[0], request.NodeIDs[0], "", netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
		t.Fatal("retired diagnostic context was reused", err)
	}
}

func TestManualCandidateDurablePreservesExclusionsBeforeChecker(t *testing.T) {
	for _, match := range []config.ResourceMatch{{Kind: "service", Value: "telegram"}, {Kind: "exact", Value: "telegram.org"}} {
		t.Run(match.Kind, func(t *testing.T) {
			a, request := disabledManualCandidateFixture(t)
			manual := []config.ResourceMatch{match}
			if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
				t.Fatal(err)
			}
			revision := a.Store.Get().Revision
			request.ExpectedRevision = &revision
			before := a.Store.Get()
			calls := 0
			a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				return dataplane.NodeCheckResult{}, nil
			})
			enqueueNodeFixture(t, a, request)
			a.runDurableServiceJob(context.Background(), time.Now())
			view := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
			if calls != 0 || len(view.Results) != 1 || view.Results[0].ErrorCode != "node-resource-refused" || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("manual candidate bypassed exclusion", view, calls)
			}
		})
	}
}

func TestManualCandidateDurableNewStopOrRevisionRevokesBeforeRecord(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "revision", true: "new-stop"}[stop], func(t *testing.T) {
			a, request := durableNodeFixture(t, 1)
			if err := a.Store.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			if err := a.Store.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			state := a.Store.Get().Services["telegram"]
			state.Enabled = false
			if err := a.Store.UpdateService("telegram", state); err != nil {
				t.Fatal(err)
			}
			revision := a.Store.Get().Revision
			request.ExpectedRevision = &revision
			beforeNodes, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			calls := 0
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				if stop {
					if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "direct"}, a.Store.Get().Revision); err != nil {
						t.Fatal(err)
					}
				} else if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
				return autofallbackResult(r, true), nil
			})
			id := enqueueNodeFixture(t, a, request)
			a.runDurableServiceJob(context.Background(), time.Now())
			afterNodes, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if calls != 1 || afterNodes.Generation != beforeNodes.Generation || durableJobAt(t, a, id).State != "failed" || stop && !a.Store.Get().ServiceControl.Stopped {
				t.Fatal("new control epoch did not revoke diagnostic result", calls, durableJobAt(t, a, id))
			}
		})
	}
}
