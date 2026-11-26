package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func newColdManagedComponentFixture(t *testing.T, mode string) (*App, dataplane.Plan) {
	t.Helper()
	store, err := config.Load(t.TempDir() + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "cold-component", Digest: "cold-component", State: "committed", Ready: true,
		Revision: store.Get().AppliedRevision, LAN: &dataplane.LANPolicyRuntimePlan{Mode: mode}, Routes: []dataplane.Route{{ServiceID: "original-service", Resolved: "xray"}}}
	m := dataplane.New(t.TempDir())
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	plan, found, err := m.Committed()
	if err != nil || !found {
		t.Fatal("real committed record is unavailable", err)
	}
	return &App{Store: store, Dataplane: m}, plan
}

// The Store, committed record and admission are real. No native runtime or
// permission fixture exists; Detector/name metadata must stay insufficient.
func TestManagedComponentObservationKeepsColdRuntimeUnknown(t *testing.T) {
	for _, tc := range []struct{ component, mode string }{
		{"nfqws2", dataplane.LANPolicyNFQWSDirectMode},
		{"xray", dataplane.LANPolicyXraySelectedTCPMode},
	} {
		t.Run(tc.component, func(t *testing.T) {
			a, plan := newColdManagedComponentFixture(t, tc.mode)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			owned, release, err := a.Operations.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			want := dataplane.ErrNFQWSScopedOwner
			if tc.component == "xray" {
				want = ErrXrayListSource
			}
			if handled, err := a.observeManagedComponentRuntime(owned, plan, tc.component); !handled || !errors.Is(err, want) {
				t.Fatal("cold owner was accepted or caller admission was reacquired", handled, err)
			}
			if err := a.Operations.WithExclusiveContext(owned, func() error { return nil }); err != nil || a.Operations.Snapshot().Active != 1 {
				t.Fatal("observation released its caller's original admission", err)
			}
			views := []components.View{{Spec: components.Spec{ID: tc.component}, Installed: true, CanInstall: true, CanUpdate: true, CanRemove: true, VerifiedVersion: "prior-installed"}}
			mergeComponentRuntimes(views, []engine.Status{{ID: tc.component, Installed: true, Configured: true, Running: true, Version: "name-only-version"}})
			a.mergeManagedComponentRuntimeObservation(owned, views)
			v := views[0]
			if v.RuntimeObservation != "unknown" || v.Running || v.RuntimeVersion != "" || v.CanInstall || v.CanUpdate || v.CanRemove || v.LifecycleBlockReason == "" || v.VerifiedVersion != "prior-installed" {
				t.Fatal("legacy inventory promoted cold runtime or altered installed verification", v)
			}
			if handled, err := a.observeManagedComponentRuntime(owned, plan, "sing-box"); !handled || err == nil {
				t.Fatal("managed lane granted a sidecar or another component", handled, err)
			}
		})
	}
}

func TestManagedComponentObservationRejectsSharedForeignAndReleasedAdmission(t *testing.T) {
	a, plan := newColdManagedComponentFixture(t, dataplane.LANPolicyXraySelectedTCPMode)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sharedRelease, err := a.Operations.Enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := a.observeManagedComponentRuntime(ctx, plan, "xray"); !handled || !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("shared admission became component authority", handled, err)
	}
	sharedRelease()
	foreign := &App{}
	foreignCtx, foreignRelease, err := foreign.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.observeManagedComponentRuntime(foreignCtx, plan, "xray"); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("foreign App admission was accepted", err)
	}
	foreignRelease()
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := a.observeManagedComponentRuntime(owned, plan, "xray"); !errors.Is(err, operationgate.ErrBusy) || a.Operations.Snapshot().Active != 0 {
		t.Fatal("released admission revived component authority", err)
	}
}

func TestManagedComponentLostCommittedRecordDoesNotFallBackToDetector(t *testing.T) {
	a, _ := newColdManagedComponentFixture(t, dataplane.LANPolicyXraySelectedTCPMode)
	if err := a.Dataplane.Record(dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, State: "committed", Noop: true}); err != nil {
		t.Fatal(err)
	}
	// Deliberately unissued slot: enough to select UNKNOWN, never authority.
	a.managedXraySelectedTCPList = &ManagedXraySelectedTCPListRuntime{active: &managedXraySelectedTCPListExecution{}}
	views := []components.View{{Spec: components.Spec{ID: "xray"}, Running: true, CanUpdate: true}}
	a.mergeManagedComponentRuntimeObservation(context.Background(), views)
	if views[0].RuntimeObservation != "unknown" || views[0].Running || views[0].CanUpdate {
		t.Fatal("lost committed intent fell back to Detector running metadata", views[0])
	}
}

func TestManagedComponentObservationUsesAlreadyBorrowedRequestAdmission(t *testing.T) {
	a, plan := newColdManagedComponentFixture(t, dataplane.LANPolicyXraySelectedTCPMode)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owned, closeRequest, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRequest()
	borrowed, closeBorrow, err := a.privateExclusiveOperation(owned)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBorrow()
	if handled, err := a.observeManagedComponentRuntime(borrowed, plan, "xray"); !handled || !errors.Is(err, ErrXrayListSource) {
		t.Fatal("observation tried to borrow the request admission twice", handled, err)
	}
	if err := a.Operations.WithExclusiveContext(borrowed, func() error { return nil }); err != nil || a.Operations.Snapshot().Active != 1 {
		t.Fatal("observation released the original request or borrow", err)
	}
}
