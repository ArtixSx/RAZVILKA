package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

type assignmentProfileCatalog struct {
	*wireguardprofile.Store
	app       *App
	exclusive []bool
}

func (c *assignmentProfileCatalog) Get(ctx context.Context, id string) (wireguardprofile.Profile, error) {
	c.exclusive = append(c.exclusive, c.app.Operations.Snapshot().Exclusive)
	return c.Store.Get(ctx, id)
}

func TestNamedWireGuardAssignmentUsesRegisteredCatalogAndWholeConfigCAS(t *testing.T) {
	a, store, adapter, _, _ := wgAPIFixture(t)
	metadata, err := store.Put(context.Background(), "backup", "Backup", wgAPIProfile(), "")
	if err != nil {
		t.Fatal(err)
	}
	owner := &assignmentProfileCatalog{Store: store, app: a}
	adapter.Profiles = owner
	handler := a.Handler(http.NotFoundHandler())
	send := func(body map[string]any, token, origin string) *httptest.ResponseRecorder {
		r := autonomyRequest("PUT", "/api/v1/services/arbitrary-site", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	before := a.Store.Get()
	body := map[string]any{"enabled": true, "route": "wireguard:backup", "expected_revision": before.Revision,
		"expected_profile_revision": metadata.Revision, "sources": []string{"192.168.1.40"}}
	if w := send(body, "", ""); w.Code != 401 {
		t.Fatal("assignment auth bypass", w.Code)
	}
	if w := send(body, awgAPIToken, "https://foreign.example"); w.Code != 403 {
		t.Fatal("assignment origin bypass", w.Code)
	}
	if len(owner.exclusive) != 0 || !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("unauthorized request reached private catalog or changed intent")
	}
	if w := send(body, awgAPIToken, ""); w.Code != 200 {
		t.Fatal("reviewed assignment refused", w.Code, w.Body.String())
	}
	after := a.Store.Get()
	if len(owner.exclusive) != 1 || !owner.exclusive[0] || after.Revision != before.Revision+1 ||
		after.Services["arbitrary-site"].WireGuardProfileRevision != metadata.Revision ||
		!reflect.DeepEqual(after.AppliedServices, before.AppliedServices) {
		t.Fatal("named assignment did not use exclusive catalog review and draft CAS")
	}
	if w := send(body, awgAPIToken, ""); w.Code != 409 || !reflect.DeepEqual(a.Store.Get(), after) {
		t.Fatal("stale configuration assignment changed draft")
	}
	options := a.appendWireGuardRouteOptions(context.Background(), nil)
	if len(options) != 1 || options[0].ID != "wireguard:backup" || options[0].WireGuardProfileRevision != metadata.Revision ||
		!options[0].Selectable || options[0].Ready || options[0].Running || strings.Contains(options[0].Description, "PASS") {
		t.Fatal("imported reserve acquired false runtime evidence", options)
	}
	a.DataplaneHost = func() dataplane.HostState { return dataplane.HostState{} }
	plan, err := a.buildDataplanePlanForScope(after, options, changeScopeAll, "")
	if err != nil || len(plan.Routes) != 1 || plan.Routes[0].WireGuardProfileRevision != metadata.Revision {
		t.Fatal("ordinary plan lost reviewed profile revision", err)
	}
	if _, err := store.Put(context.Background(), "backup", "Changed", wgAPIProfile(), metadata.Revision); err != nil {
		t.Fatal(err)
	}
	body["expected_revision"] = after.Revision
	if w := send(body, awgAPIToken, ""); w.Code != 409 || !reflect.DeepEqual(a.Store.Get(), after) {
		t.Fatal("changed profile rebound assignment")
	}
	if _, err := a.buildDataplanePlanForScope(after, options, changeScopeAll, ""); err == nil {
		t.Fatal("ordinary plan accepted changed profile after review")
	}
}

func TestNamedWireGuardAssignmentRefusesUnreviewedMetadataAndAllowsRetainedDisable(t *testing.T) {
	a, store, _, _, _ := wgAPIFixture(t)
	metadata, err := store.Put(context.Background(), "backup", "Backup", wgAPIProfile(), "")
	if err != nil {
		t.Fatal(err)
	}
	handler := a.Handler(http.NotFoundHandler())
	send := func(body map[string]any) *httptest.ResponseRecorder {
		r := autonomyRequest("PUT", "/api/v1/services/arbitrary-site", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	before := a.Store.Get()
	for _, body := range []map[string]any{
		{"enabled": true, "route": "wireguard:backup", "expected_revision": before.Revision},
		{"enabled": true, "route": "wireguard:backup", "expected_profile_revision": metadata.Revision},
		{"enabled": true, "route": "wireguard:backup", "expected_revision": before.Revision, "expected_profile_revision": strings.Repeat("A", 64)},
		{"enabled": true, "route": "wireguard:backup", "expected_revision": before.Revision, "expected_profile_revision": metadata.Revision, "wireguard_profile_revision": strings.Repeat("b", 64)},
		{"enabled": true, "route": "direct", "expected_profile_revision": metadata.Revision},
	} {
		w := send(body)
		if (w.Code != 400 && w.Code != 409) || !reflect.DeepEqual(a.Store.Get(), before) {
			t.Fatal("unreviewed profile metadata reached store", w.Code)
		}
	}
	if err := a.Store.UpdateService("arbitrary-site", config.ServiceState{Enabled: true, Route: "wireguard:backup"}); err != nil {
		t.Fatal(err)
	}
	legacy := a.Store.Get()
	options := a.appendWireGuardRouteOptions(context.Background(), []routecatalog.Option{})
	if _, err := a.buildDataplanePlanForScope(legacy, options, changeScopeAll, ""); err == nil {
		t.Fatal("ID-only legacy selection acquired Apply authority")
	}
	if err := store.Delete(context.Background(), "backup", metadata.Revision); err != nil {
		t.Fatal(err)
	}
	w := send(map[string]any{"enabled": false, "route": "wireguard:backup", "expected_revision": legacy.Revision})
	if w.Code != 200 || a.Store.Get().Services["arbitrary-site"].Enabled || a.Store.Get().Services["arbitrary-site"].WireGuardProfileRevision != "" {
		t.Fatal("missing retained profile prevented withdrawal or gained a binding", w.Code)
	}
}
