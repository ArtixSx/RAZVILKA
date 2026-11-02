package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestMihomoManualPreviewCannotBorrowOtherEnginePASS(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t) // Actual Store contains SBox service PASS.
	before := a.Store.Get()
	for _, action := range []string{"preview", "apply"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, mihomoNodePath+id+"/"+action, strings.NewReader(`{}`))
		a.mihomoNodeAction(w, r)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "MIHOMO_RUNTIME_UNAVAILABLE") {
			t.Fatalf("other-engine owner became Mihomo authority: %d %s", w.Code, w.Body.String())
		}
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 || len(a.nodeReviews.reviews) != 0 {
		t.Fatal("refused preview/apply mutated Store, executed adapter or issued token")
	}
}

func TestMihomoManualPathsUseOriginalExclusiveOperation(t *testing.T) {
	for _, action := range []string{"preview", "apply"} {
		t.Run(action, func(t *testing.T) {
			a := &App{}
			entered := false
			h := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, release, err := a.privateExclusiveOperation(r.Context())
				if err != nil {
					t.Fatal("request did not expose original retained borrower", err)
				}
				defer release()
				cleanup, err := a.Operations.ReviewExclusiveCleanup(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := cleanup.WithCurrent(ctx, func() error { entered = true; return nil }); err != nil {
					t.Fatal(err)
				}
				if release, err := a.Operations.Exclusive(context.Background()); err == nil {
					release()
					t.Fatal("new unrelated admission entered original request")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, mihomoNodePath+"node-"+strings.Repeat("1", 64)+"/"+action, strings.NewReader(`{}`))
			ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
			defer cancel()
			r = r.WithContext(ctx)
			h.ServeHTTP(w, r)
			if !entered || w.Code != http.StatusNoContent {
				t.Fatal("original exclusive operation missing", w.Code, w.Body.String())
			}
			if release, err := a.Operations.Exclusive(context.Background()); err != nil {
				t.Fatal("completed request leaked admission", err)
			} else {
				release()
			}
		})
	}
}

func TestMihomoManualReviewOwnerAndEngineAreNotTransferable(t *testing.T) {
	var store nodeRouteReviewStore
	now := time.Now()
	review, err := store.put(nodeRouteReview{Engine: "sing-box", ExpiresAt: now.Add(time.Minute), owner: [32]byte{1}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.take(review.Token, [32]byte{2}, now); ok {
		t.Fatal("foreign session consumed review")
	}
	actual, ok := store.take(review.Token, [32]byte{1}, now)
	if !ok || actual.Engine == "mihomo" {
		t.Fatal("review namespace changed")
	}
	if _, ok := store.take(review.Token, [32]byte{1}, now); ok {
		t.Fatal("authorized token replay accepted")
	}
}

func TestMihomoManualSyntaxErrorDoesNotCreateOperationAuthority(t *testing.T) {
	a := &App{}
	for _, suffix := range []string{"node-x/preview", "node-" + strings.Repeat("1", 64) + "/apply/again"} {
		w := httptest.NewRecorder()
		a.mihomoNodeAction(w, httptest.NewRequest(http.MethodPost, mihomoNodePath+suffix, strings.NewReader(`{}`)))
		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Fatal(w.Code)
		}
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("syntax refusal leaked admission", err)
	}
	release()
}

func TestMihomoManualSelectionIsCurrentCatalogWithoutRuntimeClaim(t *testing.T) {
	a, _, adapter := nodeApplyFixture(t)
	before := a.Store.Get()
	w := httptest.NewRecorder()
	a.mihomoNodeSelection(w, httptest.NewRequest(http.MethodGet, "/api/v1/mihomo/selection", nil))
	var value struct {
		Revision   uint64 `json:"revision"`
		Registered bool   `json:"runtime_registered"`
		Available  bool   `json:"live_apply_available"`
		Verified   bool   `json:"service_verified"`
		Services   []struct {
			ID string `json:"id"`
		} `json:"services"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil || w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	if value.Revision != before.Revision || value.Registered || value.Available || value.Verified || len(value.Services) != 1 || value.Services[0].ID != "telegram" {
		t.Fatal("inventory inferred runtime or domain support", w.Body.String())
	}
	if len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("selection executed or mutated")
	}
}

func TestMihomoManualBindingUsesExactCommittedImageAndCatalog(t *testing.T) {
	a, id, _ := nodeApplyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	node, err := dataplane.ReviewNodeDefaultSource(ctx, a.Nodes, "mihomo:"+id)
	if err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	service := a.catalogSnapshot().Services[0]
	b := &mihomoNodeBinding{app: a, store: a.Store, node: node, before: before, catalog: a.catalogSnapshot(), service: service, profile: "wan-0123456789ab"}
	b.self = b
	if err = b.current(ctx); err != nil {
		t.Fatal("original before image", err)
	}
	a.Catalog.Services[0].Name = "Changed catalog"
	if err = b.current(ctx); err == nil {
		t.Fatal("catalog change retained source review")
	}
	a.Catalog.Services[0].Name = service.Name
	image, undo, err := a.Store.ApplyMihomoNodeRouteScopeWithImage(service.ID, id, []string{"192.168.1.42/32"}, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.current(ctx); err == nil {
		t.Fatal("unacknowledged next image accepted")
	}
	b.after.Store(&image)
	if err = b.current(ctx); err != nil {
		t.Fatal("exact acknowledged image refused", err)
	}
	if err = undo(); err != nil {
		t.Fatal(err)
	}
	if err = b.current(ctx); err == nil {
		t.Fatal("after image accepted reverted Store")
	}
	b.after.Store(nil)
	if err = b.current(ctx); err != nil {
		t.Fatal("original rollback image refused", err)
	}
}

func TestMihomoManualCatalogClonePreservesExactEmptyAndNestedFields(t *testing.T) {
	original := catalog.Catalog{Services: []catalog.Service{{ID: "listed", CIDRs: []string{"1.1.1.0/24"}, SourceRefs: []string{}, Probes: []catalog.Probe{{ID: "required", Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectHosts: []string{}}}}}}}
	copy := mihomoNodeCatalogClone(original)
	if !reflect.DeepEqual(original, copy) {
		t.Fatal("exact catalog comparison changes during cloning")
	}
	original.Services[0].CIDRs[0] = "2.2.2.0/24"
	original.Services[0].Probes[0].Expect.StatusCodes[0] = 403
	if copy.Services[0].CIDRs[0] != "1.1.1.0/24" || copy.Services[0].Probes[0].Expect.StatusCodes[0] != 200 {
		t.Fatal("catalog mutation changed retained comparison image")
	}
}
