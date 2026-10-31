package app

import (
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/routes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuntimeLifecycleUsesOriginalAdapterAndCheckerRegistrations(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.Components = components.New()
	a.Dataplane = dataplane.New(t.TempDir())
	absent := a.runtimeLifecycle("xray")
	if absent.Operations["live_apply"].Registration != "absent" || absent.Operations["native_validation"].Registration != "unknown" {
		t.Fatal("installation or parser invented native runtime")
	}
	adapter, err := dataplane.NewProxyTunnelAdapter("xray", a.EngineConfigs, a.Dataplane.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": dataplane.NewExactXrayNodeCheckerSlots(t.TempDir(), 1)}
	lifecycle := a.runtimeLifecycle("xray")
	for _, operation := range []string{"installer", "import_export", "staged_validation", "native_validation", "isolated_probe", "live_apply", "live_health", "recovery", "rollback", "package_update"} {
		if lifecycle.Operations[operation].Registration != "registered" || lifecycle.Operations[operation].Available != nil {
			t.Fatalf("registered %s either lost or became live-ready", operation)
		}
	}
	option := routes.Option{ID: "xray", Selectable: true}
	a.prepareRouteOption(&option)
	colon := routes.Option{ID: "xray:unregistered", Selectable: true}
	a.prepareRouteOption(&colon)
	if colon.Ready {
		t.Fatal("route suffix invented exact registered adapter")
	}
	if !option.Ready {
		t.Fatal("AUTO disagrees with registered apply path")
	}
	a.Dataplane = dataplane.New(t.TempDir())
	a.prepareRouteOption(&option)
	if option.Ready {
		t.Fatal("AUTO retained absent apply registration")
	}
	awg := a.runtimeLifecycle("amneziawg")
	if awg.Operations["installer"].Registration != "absent" || awg.Operations["installer"].Available == nil || *awg.Operations["installer"].Available || len(awg.Prerequisites) == 0 {
		t.Fatal("AWG acquired invented userspace installer")
	}
	for _, id := range []string{"mihomo", "hev"} {
		lab := a.runtimeLifecycle(id)
		native := "absent"
		if id == "mihomo" {
			native = "registered"
		}
		if lab.Operations["import_export"].Registration != "lab-only" || lab.Operations["live_apply"].Registration != "absent" || lab.Operations["native_validation"].Registration != native {
			t.Fatal("lab export became production runtime", id)
		}
	}
	if got := a.runtimeLifecycle("hev").Operations["installer"]; got.Registration != "registered" || got.Available != nil {
		t.Fatal("canonical HEV component installer mapping lost or became ready", got)
	}
}

func TestRuntimeLifecycleHEVIsBoundDependencyWithUnknownAvailability(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.Components = components.New()
	a.Components.BinDir = t.TempDir()
	a.Dataplane = dataplane.New(t.TempDir())
	adapter, err := dataplane.NewProxyTunnelAdapter("xray", a.EngineConfigs, a.Dataplane.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err = dataplane.BindHEVSidecarForRecovery(context.Background(), adapter, a.Components); err != nil {
		t.Fatal(err)
	}
	if err = a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	// No executable is installed. Reporting configuration must not probe it or
	// turn this recovery-only constructor into executable/live permission.
	lifecycle := a.runtimeLifecycle("hev")
	for _, id := range []string{"runtime_preflight", "sidecar_runtime", "sidecar_recovery"} {
		operation := lifecycle.Operations[id]
		if operation.Registration != "registered" || operation.Available != nil {
			t.Fatalf("dependency %s not advisory: %+v", id, operation)
		}
	}
	for _, id := range []string{"native_validation", "live_apply", "live_health"} {
		operation := lifecycle.Operations[id]
		if operation.Registration != "absent" || operation.Available == nil || *operation.Available {
			t.Fatalf("HEV invented standalone/config validator %s: %+v", id, operation)
		}
	}
	if len(lifecycle.Prerequisites) == 0 {
		t.Fatal("parent dependency context lost")
	}
	// Shared engine API projects the exact same registration.
	a.EngineInventory = func() []engine.Status { return []engine.Status{{ID: "hev", Installed: true}} }
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/engines", nil))
	var inventory []engine.Status
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &inventory) != nil || len(inventory) != 1 || inventory[0].Lifecycle.Operations["sidecar_runtime"].Available != nil || inventory[0].Lifecycle.Operations["sidecar_runtime"].Registration != "registered" {
		t.Fatal("HEV inventory projection disagrees", w.Body.String())
	}
}
func TestRuntimeLifecycleSharedEngineHTTPInventoryDoesNotPromoteUnknown(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.EngineInventory = func() []engine.Status { return []engine.Status{{ID: "xray", Installed: true, Running: true}} }
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/engines", nil))
	var got []engine.Status
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got) != 1 || got[0].Lifecycle == nil {
		t.Fatal("shared lifecycle absent from engines API")
	}
	op := got[0].Lifecycle.Operations["live_apply"]
	if op.Registration != "absent" || op.Available == nil || *op.Available {
		t.Fatal("running binary became registered route")
	}
	raw := a.EngineInventory()
	if raw[0].Lifecycle != nil {
		t.Fatal("enrichment mutated injected inventory")
	}

}
