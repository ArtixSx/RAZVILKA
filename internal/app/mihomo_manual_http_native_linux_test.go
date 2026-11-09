//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestMihomoLiveOriginalManualHTTPApplyStop(t *testing.T) {
	t.Setenv("RAZVILKA_MIHOMO_MANUAL_HTTP_NATIVE", "1")
	runMihomoLiveOriginalNativeWorkflow(t, false)
}

func mihomoNativeHTTP(t *testing.T, ctx context.Context, server *httptest.Server, method, path string, body []byte) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

func mihomoNativeManualPreview(t *testing.T, ctx context.Context, a *App, server *httptest.Server, id string, service catalog.Service, sources []string) (dataplane.Plan, string, []byte) {
	t.Helper()
	if a.Dataplane.Capable("mihomo") || a.Dataplane.CanaryCapable("mihomo") {
		t.Fatal("manual workflow widened general/AUTO capability")
	}
	before := a.Store.Get()
	general, err := a.buildDataplanePlanForScopeContext(ctx, nodeRouteConfigForEngineScope(before, "mihomo", service.ID, id, sources), a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || general.Ready {
		t.Fatal("general planner did not retain its admission boundary", err, general.Ready)
	}
	code, raw := mihomoNativeHTTP(t, ctx, server, http.MethodGet, "/api/v1/mihomo/selection", nil)
	var selection struct {
		Registered bool `json:"runtime_registered"`
		Supported  bool `json:"manual_node_apply_supported"`
		Available  bool `json:"live_apply_available"`
		Verified   bool `json:"service_verified"`
	}
	if code != 200 || json.Unmarshal(raw, &selection) != nil || !selection.Registered || !selection.Supported || selection.Available || selection.Verified {
		t.Fatal("selection conflated structural workflow and service proof", code)
	}
	// A stale preview and all-client scope must fail before a token/effect.
	for _, request := range []map[string]any{
		{"service_id": service.ID, "sources": sources, "expected_revision": before.Revision - 1},
		{"service_id": service.ID, "sources": []string{}, "expected_revision": before.Revision},
	} {
		body, _ := json.Marshal(request)
		code, _ := mihomoNativeHTTP(t, ctx, server, http.MethodPost, mihomoNodePath+id+"/preview", body)
		if code != http.StatusConflict {
			t.Fatal("unsupported/stale preview not refused", code)
		}
	}
	// Observe the private ticket through the already-modeled WAN label only;
	// preserve the original profile result and all transaction/source checks.
	fresh := a.FreshProfile
	var ticketMu sync.Mutex
	var observedTicket *mihomoNodePlanningTicket
	a.FreshProfile = func(c context.Context) (string, error) {
		if p, ok := c.Value(mihomoNodePlanningKey{}).(*mihomoNodePlanningTicket); ok && p != nil && p.open.Load() {
			derived := context.WithValue(p.ctx, struct{ native bool }{true}, true)
			if p.current(derived, a, []dataplane.Route{{}}) == nil {
				t.Error("derived context retained private planning fact")
			}
			copyTicket := &mihomoNodePlanningTicket{self: p.self, bound: p.bound, manager: p.manager, ctx: p.ctx, sources: p.sources}
			copyTicket.open.Store(true)
			if copyTicket.current(p.ctx, a, []dataplane.Route{{}}) == nil {
				t.Error("copied planning ticket retained source")
			}
			ticketMu.Lock()
			observedTicket = p
			ticketMu.Unlock()
		}
		return fresh(c)
	}
	defer func() { a.FreshProfile = fresh }()
	body, _ := json.Marshal(map[string]any{"service_id": service.ID, "sources": sources, "expected_revision": before.Revision})
	code, raw = mihomoNativeHTTP(t, ctx, server, http.MethodPost, mihomoNodePath+id+"/preview", body)
	var preview struct {
		Ready    bool            `json:"ready"`
		Review   nodeRouteReview `json:"review"`
		Plan     dataplane.Plan  `json:"transaction"`
		Verified bool            `json:"service_verified"`
		Applied  bool            `json:"live_applied"`
	}
	if code != 200 || json.Unmarshal(raw, &preview) != nil || !preview.Ready || !preview.Plan.Ready || preview.Review.Token == "" || preview.Review.Digest != preview.Plan.Digest || preview.Verified || preview.Applied {
		t.Fatalf("actual preview failed code=%d ready=%t plan_ready=%t token_present=%t digest_matches=%t", code, preview.Ready, preview.Plan.Ready, preview.Review.Token != "", preview.Review.Digest == preview.Plan.Digest)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("preview mutated desired configuration")
	}
	ticketMu.Lock()
	completedTicket := observedTicket
	ticketMu.Unlock()
	if completedTicket == nil || completedTicket.open.Load() || completedTicket.current(completedTicket.ctx, a, preview.Plan.Routes) == nil {
		t.Fatal("completed compiler ticket escaped its request-local lifetime")
	}
	a.FreshProfile = fresh

	request := nodeApplyRequest{Engine: "mihomo", ServiceID: service.ID, Token: preview.Review.Token, Digest: preview.Review.Digest, Revision: preview.Review.Revision, Generation: preview.Review.Generation, Confirm: "APPLY_MIHOMO_NODE_ROUTE"}
	applyBody, _ := json.Marshal(request)
	// Removing the original registry owner after preview cannot execute. Restore
	// that SAME object for the subsequent explicit request, never a replacement.
	original := a.Dataplane
	a.Dataplane = nil
	code, _ = mihomoNativeHTTP(t, ctx, server, http.MethodPost, mihomoNodePath+id+"/apply", applyBody)
	a.Dataplane = original
	if code != http.StatusConflict || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("removed runtime retained admission", code)
	}
	t.Log("actual_manual_http_preview original_sources=true general_auto_closed=true stale_and_all_source_refused=true removed_runtime_refused=true service_proof=false")
	return preview.Plan, mihomoNodePath + id + "/apply", applyBody
}

func mihomoNativeManualReplayRefused(t *testing.T, ctx context.Context, a *App, server *httptest.Server, path string, body []byte) {
	t.Helper()
	before := a.Store.Get()
	code, _ := mihomoNativeHTTP(t, ctx, server, http.MethodPost, path, body)
	if code != http.StatusConflict || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("consumed review token replayed", code)
	}
	t.Log("actual_manual_http_apply committed=true replay_refused=true")
}

func mihomoNativeManualStop(t *testing.T, ctx context.Context, a *App) serviceRuntimeOutcome {
	t.Helper()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	body, _ := json.Marshal(map[string]any{"action": "stop", "expected_revision": a.Store.Get().Revision, "confirm": "STOP_OWNED_ROUTES"})
	code, raw := mihomoNativeHTTP(t, ctx, server, http.MethodPost, "/api/v1/service-control/runtime", body)
	var value struct {
		OK      bool   `json:"ok"`
		Applied bool   `json:"live_applied"`
		Code    string `json:"code"`
		Error   string `json:"error"`
	}
	if (code != http.StatusOK && code != http.StatusConflict) || json.Unmarshal(raw, &value) != nil {
		t.Fatal("actual Stop response", code)
	}
	if code == http.StatusOK && (!value.OK || !value.Applied) {
		t.Fatal("Stop lost terminal outcome", code)
	}
	return serviceRuntimeOutcome{Code: value.Code, Message: value.Error, LiveApplied: value.Applied}
}
