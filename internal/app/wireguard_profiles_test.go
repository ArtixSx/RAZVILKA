package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

func wgAPIProfile() string {
	private := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	public := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	return "[Interface]\nPrivateKey = " + private + "\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = " + public + "\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func wgAPIFixture(t *testing.T) (*App, *wireguardprofile.Store, *dataplane.WARPWireGuardAdapter, http.Handler, func(string, string, any) *httptest.ResponseRecorder) {
	t.Helper()
	a := autonomyAPIFixture(t)
	var err error
	a.Security, err = security.NewGate(awgAPIToken)
	if err != nil {
		t.Fatal(err)
	}
	a.Dataplane = dataplane.New(t.TempDir())
	adapter := dataplane.NewWireGuardAdapter(nil, t.TempDir())
	catalog := wireguardprofile.New(filepath.Join(t.TempDir(), "profiles"))
	adapter.Profiles = catalog
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerWireGuardProfileRoutes(mux)
	handler := a.Security.Middleware(mux)
	send := func(method, path string, body any) *httptest.ResponseRecorder {
		r := autonomyRequest(method, path, body)
		r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	return a, catalog, adapter, handler, send
}

func TestWireGuardProfilesCRUDCASPrivacyAndReserve(t *testing.T) {
	a, catalog, adapter, _, send := wgAPIFixture(t)
	before := a.Store.Get()
	w := send("POST", wireGuardProfilesPath, wireGuardProfileRequest{ID: "backup", Name: "Own server", Content: wgAPIProfile()})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"live_applied":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	p, err := adapter.Profiles.Get(context.Background(), "backup")
	if err != nil {
		t.Fatal(err)
	}
	revision := p.Public().Revision
	for _, path := range []string{wireGuardProfilesPath, wireGuardProfilesPath + "/backup"} {
		w = send("GET", path, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "YWFhYWFh") || strings.Contains(w.Body.String(), "PrivateKey") || strings.Contains(w.Body.String(), "vpn.example") || !strings.Contains(w.Body.String(), `"verification":"syntax-only"`) || !strings.Contains(w.Body.String(), `"reserve":true`) {
			t.Fatal("private data or false capability", w.Code, w.Body.String())
		}
	}
	if w = send("POST", wireGuardProfilesPath, wireGuardProfileRequest{ID: "backup", Name: "Own server", Content: wgAPIProfile()}); w.Code != 409 {
		t.Fatal("create overwrite", w.Code)
	}
	w = send("PUT", wireGuardProfilesPath+"/backup", wireGuardProfileRequest{Name: "Renamed", Content: wgAPIProfile(), ExpectedRevision: revision})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	p, _ = catalog.Get(context.Background(), "backup")
	if p.Public().Revision == revision {
		t.Fatal("revision did not change")
	}
	if w = send("DELETE", wireGuardProfilesPath+"/backup", wireGuardProfileRequest{ExpectedRevision: revision}); w.Code != 409 {
		t.Fatal("stale delete", w.Code)
	}
	w = send("DELETE", wireGuardProfilesPath+"/backup", wireGuardProfileRequest{ExpectedRevision: p.Public().Revision})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := catalog.Get(context.Background(), "backup"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("delete not observed by runtime", err)
	}
	if a.Store.Get().Revision != before.Revision || a.Store.Get().SafeMode != before.SafeMode {
		t.Fatal("catalog changed service configuration or Safe Mode")
	}
}

func TestWireGuardProfilesAuthCSRFAndStrictInput(t *testing.T) {
	_, _, _, handler, send := wgAPIFixture(t)
	r := httptest.NewRequest("GET", wireGuardProfilesPath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("pre-setup read exposed", w.Code)
	}
	for _, origin := range []string{"https://foreign.example", "null"} {
		r = autonomyRequest("POST", wireGuardProfilesPath, wireGuardProfileRequest{ID: "reserve", Name: "Reserve", Content: wgAPIProfile()})
		r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("CSRF accepted", origin, w.Code)
		}
	}
	for _, body := range []any{
		map[string]any{"id": "reserve", "name": "Reserve", "content": wgAPIProfile(), "extra": true},
		wireGuardProfileRequest{ID: "main", Name: "Reserve", Content: wgAPIProfile()},
		wireGuardProfileRequest{ID: "reserve", Name: "Reserve", Content: wgAPIProfile() + "PostUp = echo secret\n"},
	} {
		if w = send("POST", wireGuardProfilesPath, body); w.Code != 400 {
			t.Fatal("invalid import accepted", w.Code)
		}
	}
}

func TestWireGuardProfilesDeleteFencesDisabledAndCommittedReferences(t *testing.T) {
	for _, kind := range []string{"draft-disabled", "pending", "committed"} {
		t.Run(kind, func(t *testing.T) {
			a, catalog, _, _, send := wgAPIFixture(t)
			meta, err := catalog.Put(context.Background(), "used", "Used", wgAPIProfile(), "")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "draft-disabled" {
				if err := a.Store.UpdateService("arbitrary-site", config.ServiceState{Route: "wireguard:used", Enabled: false}); err != nil {
					t.Fatal(err)
				}
			} else {
				state := "planned"
				if kind == "committed" {
					state = "committed"
				}
				if err := a.Dataplane.Record(dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-0123456789abcdef", Digest: strings.Repeat("a", 64), State: state, Routes: []dataplane.Route{{ServiceID: "arbitrary-site", Resolved: "wireguard:used"}}}); err != nil {
					t.Fatal(err)
				}
			}
			w := send("DELETE", wireGuardProfilesPath+"/used", wireGuardProfileRequest{ExpectedRevision: meta.Revision})
			if w.Code != 409 || !strings.Contains(w.Body.String(), `"references"`) {
				t.Fatal("referenced profile removed", w.Code, w.Body.String())
			}
			if _, err := catalog.Get(context.Background(), "used"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWireGuardProfileReferenceInventoryIncludesEveryRetainedScope(t *testing.T) {
	route := "wireguard:retained"
	cfg := config.Config{Services: map[string]config.ServiceState{"draft": {Route: route}}, AppliedServices: map[string]config.ServiceState{"applied": {Route: route}}, ServiceControl: config.ServiceControl{Stopped: true, SuspendedServices: map[string]config.ServiceState{"suspended": {Route: route}}, SuspendedRoutes: map[string]string{"stop-route": route}}, NetworkPolicy: &config.NetworkPolicy{Traffic: config.TrafficSelection{DefaultRoute: route}}, AppliedNetworkPolicy: &config.NetworkPolicy{Traffic: config.TrafficSelection{DefaultRoute: route}}}
	plans := []dataplane.Plan{{Routes: []dataplane.Route{{ServiceID: "pending", Selected: route}}}, {Routes: []dataplane.Route{{ServiceID: "committed", AppliedRoute: route}}}}
	refs := wireGuardProfileReferences(cfg, plans, "retained")
	if len(refs) != 8 {
		t.Fatal("retained scope omitted", refs)
	}
	if len(wireGuardProfileReferences(cfg, plans, "other")) != 0 {
		t.Fatal("unrelated route adopted")
	}
}

func TestWireGuardProfilesForeignAndUnknownOwnersRefuseWithoutMutation(t *testing.T) {
	for _, cut := range []string{"foreign-profile", "pending-wg", "unfinished-manager", "orphan-runtime"} {
		t.Run(cut, func(t *testing.T) {
			a, catalog, adapter, _, send := wgAPIFixture(t)
			meta, err := catalog.Put(context.Background(), "reserve", "Reserve", wgAPIProfile(), "")
			if err != nil {
				t.Fatal(err)
			}
			p, _ := catalog.Get(context.Background(), "reserve")
			switch cut {
			case "foreign-profile":
				// The metadata comes from the same owned catalog; replace its file
				// directly to model an unrelated writer that ignores the API lease.
				// Obtain a second registered explicit root for this refusal case.
				root := t.TempDir()
				foreign := []byte(`{"owner":"foreign","private":"retained"}`)
				if err := os.WriteFile(filepath.Join(root, "reserve.json"), foreign, 0600); err != nil {
					t.Fatal(err)
				}
				adapter.Profiles = wireguardprofile.New(root)
				w := send("DELETE", wireGuardProfilesPath+"/reserve", wireGuardProfileRequest{ExpectedRevision: meta.Revision})
				if w.Code != 409 {
					t.Fatal(w.Code)
				}
				got, _ := os.ReadFile(filepath.Join(root, "reserve.json"))
				if string(got) != string(foreign) {
					t.Fatal("foreign file modified")
				}
				return
			case "pending-wg":
				if err := os.MkdirAll(filepath.Join(adapter.StateRoot, "wg-policy-operation"), 0700); err != nil {
					t.Fatal(err)
				}
			case "unfinished-manager":
				data, _ := json.Marshal(map[string]any{"plan_id": "pending", "digest": "hash", "state": "applying"})
				if err := os.WriteFile(filepath.Join(a.Dataplane.StateRoot, "latest-execution.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "orphan-runtime":
				if err := os.MkdirAll(adapter.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(adapter.RuntimeConfigPath, []byte(wgAPIProfile()), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := send("DELETE", wireGuardProfilesPath+"/reserve", wireGuardProfileRequest{ExpectedRevision: meta.Revision})
			if w.Code != 409 {
				t.Fatal("unknown reference owner accepted", cut, w.Code, w.Body.String())
			}
			got, err := catalog.Get(context.Background(), "reserve")
			if err != nil || got.Public().Revision != p.Public().Revision {
				t.Fatal("profile changed on refusal", err)
			}
		})
	}
}

type wgCatalogCut struct {
	*wireguardprofile.Store
	afterPut   func()
	refuseUndo bool
}

func (c *wgCatalogCut) Put(ctx context.Context, id, name, content, revision string) (wireguardprofile.Metadata, error) {
	meta, err := c.Store.Put(ctx, id, name, content, revision)
	if err == nil && c.afterPut != nil {
		after := c.afterPut
		c.afterPut = nil
		after()
	}
	return meta, err
}

func (c *wgCatalogCut) Delete(ctx context.Context, id, revision string) error {
	if c.refuseUndo {
		return wireguardprofile.ErrRevision
	}
	return c.Store.Delete(ctx, id, revision)
}

func TestWireGuardProfilesDetectPlanChangeAndReportRestorationOutcome(t *testing.T) {
	for _, refuseUndo := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "unknown"}[refuseUndo], func(t *testing.T) {
			a, catalog, adapter, _, send := wgAPIFixture(t)
			cut := &wgCatalogCut{Store: catalog, refuseUndo: refuseUndo}
			cut.afterPut = func() {
				if err := a.Dataplane.Record(dataplane.Plan{SchemaVersion: 1, PlanID: "dp-0123456789abcdef", Digest: strings.Repeat("a", 64), State: "reviewed"}); err != nil {
					t.Fatal(err)
				}
			}
			adapter.Profiles = cut
			w := send("POST", wireGuardProfilesPath, wireGuardProfileRequest{ID: "cut", Name: "Cut", Content: wgAPIProfile()})
			if w.Code != 409 || !strings.Contains(w.Body.String(), `"outcome":"unconfirmed"`) || !strings.Contains(w.Body.String(), map[bool]string{false: `"restoration_confirmed":true`, true: `"restoration_confirmed":false`}[refuseUndo]) {
				t.Fatal("late change reported as saved", w.Code, w.Body.String())
			}
			_, err := catalog.Get(context.Background(), "cut")
			if !refuseUndo && !errors.Is(err, os.ErrNotExist) || refuseUndo && err != nil {
				t.Fatal("restoration outcome mismatched retained file", err)
			}
		})
	}
}

func TestWireGuardProfilesRespectExistingConfigurationLease(t *testing.T) {
	a, catalog, _, _, send := wgAPIFixture(t)
	session, err := a.Store.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	w := send("POST", wireGuardProfilesPath, wireGuardProfileRequest{ID: "busy", Name: "Busy", Content: wgAPIProfile()})
	if w.Code != 409 {
		t.Fatal("bypassed full configuration lease", w.Code, w.Body.String())
	}
	if _, err := catalog.Get(context.Background(), "busy"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote during lease refusal", err)
	}
}
