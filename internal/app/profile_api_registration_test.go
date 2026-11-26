package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

type registeredWGProfileCatalog struct {
	*wireguardprofile.Store
	app        *App
	admissions []bool
}

func (c *registeredWGProfileCatalog) Put(ctx context.Context, id, name, content, revision string) (wireguardprofile.Metadata, error) {
	c.admissions = append(c.admissions, c.app.Operations.Snapshot().Exclusive)
	return c.Store.Put(ctx, id, name, content, revision)
}
func (c *registeredWGProfileCatalog) Delete(ctx context.Context, id, revision string) error {
	c.admissions = append(c.admissions, c.app.Operations.Snapshot().Exclusive)
	return c.Store.Delete(ctx, id, revision)
}

func TestRegisteredWireGuardProfileAPIUsesSecurityAndExclusiveOwnerAdmission(t *testing.T) {
	a, catalog, adapter, _, _ := wgAPIFixture(t)
	owner := &registeredWGProfileCatalog{Store: catalog, app: a}
	adapter.Profiles = owner
	handler := a.Handler(http.NotFoundHandler())
	send := func(method, path, token string, body any, origin string) *httptest.ResponseRecorder {
		r := autonomyRequest(method, path, body)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := send("GET", wireGuardProfilesPath, "", nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated registered read", w.Code)
	}
	body := wireGuardProfileRequest{ID: "backup", Name: "Backup", Content: wgAPIProfile()}
	if w := send("POST", wireGuardProfilesPath, awgAPIToken, body, "https://foreign.example"); w.Code != 403 || len(owner.admissions) != 0 {
		t.Fatal("registered CSRF refusal", w.Code, owner.admissions)
	}
	if w := send("POST", wireGuardProfilesPath, awgAPIToken, body, ""); w.Code != 200 {
		t.Fatal("registered create", w.Code, w.Body.String())
	}
	profile, err := adapter.Profiles.Get(context.Background(), "backup")
	if err != nil {
		t.Fatal(err)
	}
	if w := send("PUT", wireGuardProfilesPath+"/backup", awgAPIToken, wireGuardProfileRequest{Name: "Renamed", Content: wgAPIProfile(), ExpectedRevision: profile.Public().Revision}, ""); w.Code != 200 {
		t.Fatal("registered replace", w.Code, w.Body.String())
	}
	profile, err = adapter.Profiles.Get(context.Background(), "backup")
	if err != nil {
		t.Fatal(err)
	}
	if w := send("DELETE", wireGuardProfilesPath+"/backup", awgAPIToken, wireGuardProfileRequest{ExpectedRevision: profile.Public().Revision}, ""); w.Code != 200 {
		t.Fatal("registered delete", w.Code, w.Body.String())
	}
	if len(owner.admissions) != 3 {
		t.Fatal("missing owner catalog calls", owner.admissions)
	}
	for _, exclusive := range owner.admissions {
		if !exclusive {
			t.Fatal("catalog mutation borrowed shared admission", owner.admissions)
		}
	}
	if a.Operations.Snapshot().Exclusive {
		t.Fatal("registered request retained admission")
	}
}
