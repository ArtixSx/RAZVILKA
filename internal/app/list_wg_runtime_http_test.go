package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestListWGOrdinaryPlanApplyRefusesMissingOriginalRuntime(t *testing.T) {
	f := newListWGSourceFixture(t)
	before := f.a.Store.Get()
	for _, action := range []string{"plan", "apply"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil)
		fn := f.a.plan
		if action == "apply" {
			body, _ := json.Marshal(map[string]any{"expected_revision": before.Revision, "reviewed_digest": strings.Repeat("a", 64)})
			request = httptest.NewRequest(http.MethodPost, "/api/v1/apply", strings.NewReader(string(body)))
			fn = f.a.apply
		}
		response := httptest.NewRecorder()
		f.a.operationMiddleware(http.HandlerFunc(fn)).ServeHTTP(response, request)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "WG_LIST_REVIEW") {
			t.Fatal("ordinary request escaped closed WG dispatch", action, response.Code, response.Body.String())
		}
	}
	if f.a.Store.Get().Revision != before.Revision {
		t.Fatal("refused request changed Store")
	}
	if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
		t.Fatal("refused request started source or effect child", err)
	}
}

func TestListWGColdCommittedMetadataCannotGrantCurrentOrComponent(t *testing.T) {
	f := newListWGSourceFixture(t)
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-cold-wg", Digest: strings.Repeat("a", 64), State: "committed", Ready: true, Revision: f.a.Store.Get().AppliedRevision, LAN: &dataplane.LANPolicyRuntimePlan{}, Routes: []dataplane.Route{{ServiceID: "listed", Resolved: "wireguard"}}}
	if err := f.a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	plan, found, err := f.a.Dataplane.Committed()
	if err != nil || !found {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := f.a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if handled, err := f.a.observeCommittedManagedWG(ctx, plan); !handled || err == nil {
		t.Fatal("cold journal supplied actual retained owner", handled, err)
	}
	views := []components.View{{Spec: components.Spec{ID: "wireguard"}, Installed: true, Running: true, RuntimeVersion: "name-only", VerifiedVersion: "installed", CanInstall: true, CanUpdate: true, CanRemove: true}}
	f.a.mergeManagedComponentRuntimeObservation(ctx, views)
	if v := views[0]; v.RuntimeObservation != "unknown" || v.Running || v.RuntimeVersion != "" || v.CanInstall || v.CanUpdate || v.CanRemove || v.VerifiedVersion != "installed" {
		t.Fatal("cold metadata supplied live component or changed installation facts", v)
	}
}
