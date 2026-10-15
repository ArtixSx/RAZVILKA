package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestRememberedCookieCannotAuthorizeMissingAccountOrSurviveNewSetup(t *testing.T) {
	g, oldToken, dir, now := persistenceSession(t)
	credentialPath := filepath.Join(dir, "admin.credentials.json")
	if err := os.Remove(credentialPath); err != nil {
		t.Fatal(err)
	}
	if err := g.ConfigureCredentials(credentialPath); err != nil {
		t.Fatal(err)
	}
	if g.Authenticated(sessionRequest(oldToken)) {
		t.Fatal("cached cookie retained admin permission without an account")
	}

	restarted := rememberedGate(t, dir, now)
	if !restarted.SetupRequired() || restarted.Authenticated(sessionRequest(oldToken)) || len(restarted.sessions) != 0 {
		t.Fatal("old remembered cookie was loaded without its account")
	}
	setups := 0
	h := restarted.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := restarted.Setup("replacement-admin", "replacement-long-passphrase", r); err != nil {
			t.Fatal(err)
		}
		setups++
		w.WriteHeader(http.StatusOK)
	}))
	request := func(recovery bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", nil)
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(sessionRequest(oldToken).Cookies()[0])
		if recovery {
			r.Header.Set("Authorization", "Bearer "+rememberedTestToken)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request(false); w.Code != http.StatusUnauthorized || setups != 0 {
		t.Fatalf("old cookie authorized new account setup: status=%d setups=%d", w.Code, setups)
	}
	if w := request(true); w.Code != http.StatusOK || setups != 1 {
		t.Fatalf("recovery key could not set up account: status=%d setups=%d", w.Code, setups)
	}
	if restarted.Authenticated(sessionRequest(oldToken)) {
		t.Fatal("old cookie acquired the new account's permission")
	}
	again := rememberedGate(t, dir, now)
	if again.SetupRequired() || again.Username() != "replacement-admin" || again.Authenticated(sessionRequest(oldToken)) {
		t.Fatal("old cookie survived successful setup and restart")
	}
}

func TestAccountSetupDoesNotCreateCredentialsBeforeOldSessionRevocationIsDurable(t *testing.T) {
	g, oldToken, dir, now := persistenceSession(t)
	path := filepath.Join(dir, "admin.credentials.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := g.ConfigureCredentials(path); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("old-session revocation directory sync failure")
	g.privateDirSync = func(*ownedfs.Root) error { return injected }
	token, err := g.Setup("replacement-admin", "replacement-long-passphrase")
	if !errors.Is(err, injected) || token != "" || !g.SetupRequired() {
		t.Fatalf("setup confirmed failed old-session revocation: token=%t setup=%t err=%v", token != "", g.SetupRequired(), err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup created a new account before durable revocation: %v", err)
	}
	if g.Authenticated(sessionRequest(oldToken)) || rememberedGate(t, dir, now).Authenticated(sessionRequest(oldToken)) {
		t.Fatal("old cookie authorized a missing account after failed setup")
	}
}
