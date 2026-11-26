package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Store, consent, control and scope are the original objects. The existing
// physical/WAN fixture supplies facts only; it grants no native packet proof.
func TestListScopeSelectedProjectionKeepsBothSetsAndDetachedCompilerIntent(t *testing.T) {
	a, old, model := listScopeFixture(t, "mac", false)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, a, func(ctx context.Context) {
		before := a.Store.Get()
		policy := config.CloneNetworkPolicy(before.NetworkPolicy)
		policy.Revision++
		policy.Clients.DeviceIDs = []string{"mac-02-00-00-00-00-03", "mac-02-00-00-00-00-01"}
		policy.Clients.ExcludedDeviceIDs = []string{"mac-02-00-00-00-00-04", "mac-02-00-00-00-00-02"}
		consent := before.DefaultRouteConsent
		if _, err := a.Store.ApproveDefaultRouteConsent(ctx, before, policy, consent.Grants, consent.InstallationID, consent.Sequence); err != nil {
			t.Fatal(err)
		}
		model.facts.Devices = []physicalscope.Device{
			{ID: "mac-02-00-00-00-00-01", MAC: "02:00:00:00:00:01", Interface: "br0", IfIndex: 3, SegmentID: "Bridge0", Addresses: []string{"192.168.1.40", "fd00::40"}},
			{ID: "mac-02-00-00-00-00-02", MAC: "02:00:00:00:00:02", Interface: "br0", IfIndex: 3, SegmentID: "Bridge0", Addresses: []string{"192.168.1.41", "fd00::41"}},
			{ID: "mac-02-00-00-00-00-03", MAC: "02:00:00:00:00:03", Interface: "br0", IfIndex: 3, SegmentID: "Bridge0", Addresses: []string{"192.168.1.42", "fd00::42"}},
			{ID: "mac-02-00-00-00-00-04", MAC: "02:00:00:00:00:04", Interface: "br0", IfIndex: 3, SegmentID: "Bridge0", Addresses: []string{"192.168.1.43", "fd00::43"}},
		}
		b, err := newListScopeBinding(ctx, a, model.acquire)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		actualConfig := a.Store.Get()
		selection, err := b.selection(ctx)
		want := &physicalscope.SelectedDeviceProjection{
			DeviceIDs:         []string{"mac-02-00-00-00-00-01", "mac-02-00-00-00-00-03"},
			ExcludedDeviceIDs: []string{"mac-02-00-00-00-00-02", "mac-02-00-00-00-00-04"},
		}
		if err != nil || !reflect.DeepEqual(selection.SelectedDevices, want) || selection.Revision != actualConfig.DefaultRouteConsent.ApprovalRevision || selection.PolicyRevision != actualConfig.NetworkPolicy.Revision {
			t.Fatal("physical selection lost the approved positive or negative cohort", selection, err)
		}
		compiled := listScopeCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, compiled); err != nil {
			t.Fatal(err)
		}
		plan := compiled.LAN()
		frozenPlan := dataplane.CloneLANPolicyRuntime(plan)
		selection.SelectedDevices.DeviceIDs[0] = "foreign-selected"
		selection.SelectedDevices.ExcludedDeviceIDs[0] = "foreign-excluded"
		selection.SegmentIDs[0] = "foreign-segment"
		fresh, err := b.selection(ctx)
		if err != nil || !reflect.DeepEqual(fresh.SelectedDevices, want) || !reflect.DeepEqual(a.Store.Get(), actualConfig) {
			t.Fatal("returned projection changed the original consent", fresh, err)
		}
		if err := b.ScopeCheck(ctx, plan); err != nil || !reflect.DeepEqual(compiled.LAN(), frozenPlan) {
			t.Fatal("projection changed the compiled LAN intent", err)
		}
		if err := a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.selection(ctx); err == nil {
			t.Fatal("changed config supplied the old physical projection")
		}
	})
}

func TestListScopeLANExceptDoesNotIssueSelectedProjection(t *testing.T) {
	a, b, _ := listScopeFixture(t, "all", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		selection, err := b.selection(ctx)
		if err != nil || selection.SelectedDevices != nil {
			t.Fatal("whole LAN consent acquired selected-device semantics", selection, err)
		}
	})
}
