package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Actual source/Store/NodeStore/control/compilation. The physical, WAN and
// recorded-check fixtures are explicit models; no native owner/health grant.
func serviceModeSourceFixture(t *testing.T, use func(*listXraySourceFixture, context.Context, *XrayListRuntimeSource, dataplane.Plan)) {
	t.Helper()
	f, service := newSelectedTCPInlineScopeFixture(t)
	if err := f.scope.Close(); err != nil {
		t.Fatal(err)
	}
	mode := "manual"
	if err := f.a.Store.UpdateServiceControl(&mode, nil, f.a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, f.a, func(ctx context.Context) {
		var err error
		f.scope, err = newListScopeBinding(ctx, f.a, f.physical.acquire)
		if err != nil {
			t.Fatal(err)
		}
		// Production installs its original VerifyRetainedIncarnation reader.
		// This explicit physics model likewise compares retained facts without
		// calling the old forward config selection after the mode-only writer.
		f.scope.verifyCleanupPhysical = func(context.Context) error { return f.physical.verifyErr }
		source, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		prepared, err := source.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.close()
		input := (&DefaultRouteExecutor{app: f.a}).input(prepared.compilation, source.expected)
		plan := defaultRouteClonePlan(dataplane.Plan{Routes: input.Routes, LAN: prepared.compilation.LAN(), NetworkProfileID: input.NetworkProfileID})
		_, started, finished := xrayAssemblySourceCAS(t, source)
		if err := source.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		use(f, ctx, source, plan)
	})
}

func TestServiceModeSourceConsumesOnlyActualReceiptWithoutRevivingForwardScope(t *testing.T) {
	serviceModeSourceFixture(t, func(f *listXraySourceFixture, ctx context.Context, source *XrayListRuntimeSource, plan dataplane.Plan) {
		before, originalScope := source.expected, source.scope.expected
		cleanup, err := f.a.Operations.ReviewExclusiveCleanup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// The round context is genuinely canceled; its retained comparison can
		// change only under this current actual operation and the Store receipt.
		source.cancel()
		undo, receipt, err := source.store.UpdateManualToAutoReviewed(ctx, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.acceptServiceModeComparison(ctx, receipt, plan, nil, false); err != nil {
			t.Fatal(err)
		}
		if source.expected.ServiceControl.Mode != "auto" || !reflect.DeepEqual(source.expected, source.store.Get()) ||
			!reflect.DeepEqual(source.scope.expected, originalScope) || source.ctx.Err() == nil {
			t.Fatal("mode comparison reopened original scope/context or lost Store identity")
		}
		if err := receipt.Accept(ctx); err != nil {
			t.Fatal(err)
		}
		if source.acceptServiceModeComparison(ctx, receipt, plan, nil, false) == nil {
			t.Fatal("accepted receipt adopted twice")
		}
		if err := undo(); err != nil {
			t.Fatal(err)
		}
		if err := source.acceptServiceModeComparison(ctx, receipt, plan, cleanup, true); err != nil {
			t.Fatal("actual original undo comparison", err)
		}
		if !reflect.DeepEqual(source.expected, before) || source.Current(ctx) == nil {
			t.Fatal("actual undo revived canceled original forward owner")
		}
	})
}

func TestServiceModeSourceRefusesForeignWriterWANAndScopeDrift(t *testing.T) {
	for _, change := range []string{"unissued", "foreign-Store", "WAN", "scope"} {
		t.Run(change, func(t *testing.T) {
			serviceModeSourceFixture(t, func(f *listXraySourceFixture, ctx context.Context, source *XrayListRuntimeSource, plan dataplane.Plan) {
				before := source.expected
				_, receipt, err := source.store.UpdateManualToAutoReviewed(ctx, before.Revision)
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "unissued":
					receipt = &config.ServiceModeCommitReview{}
				case "foreign-Store":
					foreign, err := config.Load(filepath.Join(t.TempDir(), "foreign.json"))
					if err != nil {
						t.Fatal(err)
					}
					f.a.Store = foreign
					defer func() { f.a.Store = source.store }()
				case "WAN":
					f.physical.network = "wan-foreign"
				case "scope":
					plan.LAN.Ingress[0].Sources = []string{"192.168.1.41/32"}
				}
				if source.acceptServiceModeComparison(ctx, receipt, plan, nil, false) == nil || !reflect.DeepEqual(source.expected, before) {
					t.Fatal("changed receipt/owner/physics adopted", change)
				}
			})
		})
	}
}

func TestServiceModePublicPutCannotCreateMissingManagedOwner(t *testing.T) {
	serviceModeSourceFixture(t, func(f *listXraySourceFixture, ctx context.Context, source *XrayListRuntimeSource, plan dataplane.Plan) {
		before := f.a.Store.Get()
		wake := make(chan struct{}, 1)
		f.a.reconciler.wake = wake
		body, _ := json.Marshal(map[string]any{"expected_revision": before.Revision, "mode": "auto", "confirm": "SAVE_SERVICE_CONTROL"})
		request := httptest.NewRequest("PUT", "/api/v1/service-control", bytes.NewReader(body)).WithContext(ctx)
		response := httptest.NewRecorder()
		// Actual public handler and Store, with no original managed runtime.
		f.a.serviceControl(response, request)
		if response.Code != 409 || !reflect.DeepEqual(f.a.Store.Get(), before) || len(wake) != 0 {
			t.Fatal("saved selection/plan data manufactured a managed owner", response.Code)
		}
	})
}

func TestServiceModeAutonomyWizardAlreadyAutoPreservesActualConfigImage(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	p := a.autonomyPolicy()
	response := httptest.NewRecorder()
	a.autonomyAPI(response, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if response.Code != 200 || !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("unchanged wizard mode rewrote actual runtime config", response.Code, response.Body.String())
	}
	if a.autonomyPolicy().Revision <= p.Revision {
		t.Fatal("actual autonomy policy save was skipped")
	}
}

func TestServiceModeSourceRejectsCanceledOperationBeforeAdoption(t *testing.T) {
	serviceModeSourceFixture(t, func(f *listXraySourceFixture, ctx context.Context, source *XrayListRuntimeSource, plan dataplane.Plan) {
		before := source.expected
		_, receipt, err := source.store.UpdateManualToAutoReviewed(ctx, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		canceled, cancel := context.WithTimeout(ctx, time.Nanosecond)
		defer cancel()
		<-canceled.Done()
		if source.acceptServiceModeComparison(canceled, receipt, plan, nil, false) == nil || !reflect.DeepEqual(source.expected, before) {
			t.Fatal("expired current operation adopted mode")
		}
	})
}
