package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/security"
)

func TestSourceOfflineActualHandlerRetainsSecurityAndReadOnlySavedCatalog(t *testing.T) {
	a, root := sourceOfflineFixture(t, "fresh")
	var err error
	a.Security, err = security.NewGate(awgAPIToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Security.ConfigureCredentials(filepath.Join(root, "admin.json")); err != nil {
		t.Fatal(err)
	}
	session, err := a.Security.Setup("admin", "offline actual handler fixture password")
	if err != nil {
		t.Fatal(err)
	}
	cookies := httptest.NewRecorder()
	security.SetSessionCookie(cookies, httptest.NewRequest(http.MethodGet, "http://router.local", nil), session)
	cookie := cookies.Result().Cookies()[0]
	beforeFiles, beforeStates := sourceOfflineFiles(t, root), a.Sources.List()
	handler := a.Handler(http.NotFoundHandler())
	send := func(method, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, sourceOfflineCatalogPath, nil)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := send("GET", ""); w.Code != 401 {
		t.Fatal("ordinary route bypassed security", w.Code)
	}
	w := send("GET", awgAPIToken)
	var view sourceOfflineCatalogView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || !view.Offline || !view.ReadOnly || len(view.Sources) != 1 || view.Sources[0].Ready || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("ordinary route lost offline boundary", w.Code)
	}
	if w := send("POST", awgAPIToken); w.Code != 405 || w.Header().Get("Allow") != "GET" {
		t.Fatal("readonly route accepted mutation", w.Code)
	}
	if !reflect.DeepEqual(beforeFiles, sourceOfflineFiles(t, root)) || !reflect.DeepEqual(beforeStates, a.Sources.List()) {
		t.Fatal("ordinary route renewed/wrote saved state")
	}
}
