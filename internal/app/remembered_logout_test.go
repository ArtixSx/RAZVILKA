package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/security"
)

func TestSessionRevocationHTTPDoesNotClaimSuccessWhenStorageFails(t *testing.T) {
	dir := t.TempDir()
	gate, err := security.NewGate("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureCredentials(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureRememberedSessions(filepath.Join(dir, "sessions.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	token, err := gate.LoginRemembered("admin", "correct-horse-battery-staple", true)
	if err != nil {
		t.Fatal(err)
	}
	cookies := httptest.NewRecorder()
	security.SetRememberedSessionCookie(cookies, httptest.NewRequest("GET", "/", nil), token)
	ordinary, err := gate.Login("admin", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	ordinaryCookies := httptest.NewRecorder()
	security.SetSessionCookie(ordinaryCookies, httptest.NewRequest("GET", "/", nil), ordinary)
	blocker := filepath.Join(dir, "unavailable-storage")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = gate.ConfigureRememberedSessions(filepath.Join(blocker, "sessions.json"))
	a := &App{Security: gate}
	for _, path := range []string{"/api/v1/auth/logout", "/api/v1/auth/sessions/revoke-others"} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		// Logout revokes the remembered cookie; revoke-others revokes it from
		// an ordinary session so both must persist before reporting success.
		if strings.HasSuffix(path, "/logout") {
			r.AddCookie(cookies.Result().Cookies()[0])
		} else {
			r.AddCookie(ordinaryCookies.Result().Cookies()[0])
		}
		w := httptest.NewRecorder()
		if strings.HasSuffix(path, "/logout") {
			a.authLogout(w, r)
		} else {
			a.authSessionAction(w, r)
		}
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "SESSION_REVOCATION_FAILED") || len(w.Result().Cookies()) != 0 {
			t.Fatalf("%s: code=%d cookies=%v body=%s", path, w.Code, w.Result().Cookies(), w.Body.String())
		}
	}
}
