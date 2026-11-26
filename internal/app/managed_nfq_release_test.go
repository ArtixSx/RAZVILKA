package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

type managedNFQReleaseAdmissionContext struct {
	context.Context
	queries *int
}

func (c managedNFQReleaseAdmissionContext) Value(key any) any {
	if _, ok := key.(operationContextKey); ok {
		*c.queries++
	}
	return c.Context.Value(key)
}

// Structural ownership alone used to reach the exclusive operation. The
// deliberately unusable control/tool objects prove the release refusal occurs
// before those producers, not by making their checks pass.
func managedNFQReleaseFixture(t *testing.T) (*App, *ManagedNFQWSListRuntime) {
	t.Helper()
	a := managedNFQInitialControlFixture(t)
	a.Dataplane = &dataplane.Manager{}
	r := &ManagedNFQWSListRuntime{app: a, manager: a.Dataplane, panel: context.Background(),
		provider: netidentity.NewProcProvider(), tools: &startuptools.Lease{}, inventory: &dataplane.BackendInventory{},
		gate: &dataplane.NetworkPolicyAdapter{}, checks: &dataplane.NetworkPolicyChecks{}, control: &operationgate.ControlEpochReview{}}
	r.self = r
	a.managedNFQList = r
	if !r.original() {
		t.Fatal("fixture lacks original structural tuple")
	}
	return a, r
}

func TestManagedNFQReleaseRefusesNewStartBeforeAdmission(t *testing.T) {
	a, r := managedNFQReleaseFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	queries := 0
	ctx = managedNFQReleaseAdmissionContext{Context: ctx, queries: &queries}
	before, gate := a.Store.Get(), a.Operations.Snapshot()
	for _, reviewed := range []bool{false, true} {
		var review *applyReview
		if reviewed {
			review = &applyReview{}
		}
		result, err := r.startReviewed(ctx, "chat", "tcp", "ipv4", changeScopeAll, review)
		var refusal *capabilityRefusal
		if !errors.As(err, &refusal) || refusal.Code != capabilityManagedNFQDeferred || result.State != "" {
			t.Fatalf("new start escaped release gate: %+v %v", result, err)
		}
	}
	_, _, err := r.review(ctx, "chat", "tcp", "ipv4", changeScopeAll)
	var refusal *capabilityRefusal
	if !errors.As(err, &refusal) || refusal.Code != capabilityManagedNFQDeferred ||
		!reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(gate, a.Operations.Snapshot()) || queries != 0 || r.active != nil || r.pending != nil {
		t.Fatal("preview attempted admission or mutated owner", err)
	}
	foreign := &ManagedNFQWSListRuntime{self: r, app: a, manager: r.manager, panel: r.panel,
		provider: r.provider, tools: r.tools, inventory: r.inventory, gate: r.gate, checks: r.checks, control: r.control}
	if _, err := foreign.Start(ctx, "chat", "tcp", "ipv4"); !errors.Is(err, dataplane.ErrNFQWSScopedOwner) {
		t.Fatal("copied provenance changed original refusal", err)
	}
}

func TestManagedNFQReleaseKeepsExistingOwnerRefusalsAndCleanup(t *testing.T) {
	a, r := managedNFQReleaseFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Existing active state must reach the old review validation, not a release
	// refusal and not success from the mere presence of the retained pointer.
	r.active = &managedNFQWSListExecution{}
	if a.managedNFQNewApplyRefusal("chat") != nil {
		t.Fatal("active review hidden")
	}
	_, err := r.startReviewed(ctx, "chat", "tcp", "ipv4", changeScopeAll, &applyReview{})
	var refusal *capabilityRefusal
	if !errors.Is(err, dataplane.ErrNFQWSScopedOwner) || errors.As(err, &refusal) {
		t.Fatal(err)
	}
	r.active = nil
	r.pending = &managedNFQWSListExecution{}
	_, err = r.Start(ctx, "chat", "tcp", "ipv4")
	if !errors.Is(err, dataplane.ErrNFQWSScopedOwner) || errors.As(err, &refusal) {
		t.Fatal(err)
	}
	for _, call := range []func(context.Context) error{r.Current, r.Stop, r.Close} {
		err := call(ctx)
		if err == nil || errors.As(err, &refusal) {
			t.Fatal("cleanup/inspection replaced by release refusal", err)
		}
	}
	if r.pending == nil || r.closed {
		t.Fatal("uncertain cleanup ownership lost")
	}
}

func TestManagedNFQReleaseHTTPPreviewApplyAndAutoAgree(t *testing.T) {
	a, server := listModeCapabilityFixture(t)
	setCapabilityServices(t, a, map[string]string{"chat": "nfqws2"})
	requireCapabilityRefusal(t, a, server, capabilityManagedNFQDeferred, "")
	if got := a.autonomyCapabilityRefusal(a.Store.Get(), "chat", "nfqws2"); got == nil || got.Code != capabilityManagedNFQDeferred {
		t.Fatal("AUTO differs from manual release refusal", got)
	}
	// The separate lab start endpoint converges on the same common boundary.
	b, _ := managedNFQReleaseFixture(t)
	w := &managedNFQDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	b.managedNFQListRuntimeHTTP(w, httptest.NewRequest(http.MethodPost, managedNFQListRuntimePath,
		strings.NewReader(`{"action":"start","service_id":"chat","protocol":"tcp","ip_family":"ipv4"}`)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), capabilityManagedNFQDeferred) {
		t.Fatalf("lab start bypass: %d %s", w.Code, w.Body.String())
	}
}

func TestManagedNFQReleaseChoicePreservesLegacyAndObservedState(t *testing.T) {
	a, _ := listModeCapabilityFixture(t)
	original := routecatalog.Option{ID: "nfqws2", Installed: true, Configured: true, Running: true, Selectable: true, Ready: true}
	option := original
	a.restrictManagedNFQRouteOption(&option)
	if option.Selectable || option.Ready || !option.Installed || !option.Configured || !option.Running || option.Description == "" {
		t.Fatal("managed choice hid actual state or offered new Apply", option)
	}
	legacy := managedNFQInitialControlFixture(t)
	option = original
	legacy.restrictManagedNFQRouteOption(&option)
	if !reflect.DeepEqual(original, option) || legacy.autonomyCapabilityRefusal(config.Default(), "chat", "nfqws2") != nil {
		t.Fatal("legacy standalone NFQ changed")
	}
	_, _, _, _, handles, _ := legacy.managedNFQApplyTarget(config.Default(), changeScopeAll)
	if handles {
		t.Fatal("legacy target entered managed lane")
	}
}
