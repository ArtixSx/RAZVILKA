package security

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const rememberedTestToken = "0123456789abcdef0123456789abcdef"

// rememberedGate models one panel process: the same credential and session
// files are reopened by every new gate, as after a restart.
func rememberedGate(t *testing.T, dir string, now time.Time) *Gate {
	t.Helper()
	gate, err := NewGate(rememberedTestToken)
	if err != nil {
		t.Fatal(err)
	}
	gate.now = func() time.Time { return now }
	if err := gate.ConfigureCredentials(filepath.Join(dir, "admin.credentials.json")); err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureRememberedSessions(filepath.Join(dir, "admin.sessions.json")); err != nil {
		t.Fatal(err)
	}
	return gate
}

func sessionRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/system", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	return r
}

func TestRememberedSessionSurvivesRestartAndStoresOnlyItsHash(t *testing.T) {
	dir, now := t.TempDir(), time.Unix(1_800_000_000, 0)
	gate := rememberedGate(t, dir, now)
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	remembered, err := gate.LoginRemembered("admin", "correct-horse-battery-staple", true)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := gate.Login("admin", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "admin.sessions.json"))
	if err != nil || strings.Contains(string(data), remembered) || strings.Contains(string(data), ordinary) {
		t.Fatalf("session file missing or holds a token: %v", err)
	}
	restarted := rememberedGate(t, dir, now.Add(29*24*time.Hour))
	if !restarted.Authenticated(sessionRequest(remembered)) {
		t.Fatal("remembered session did not survive a restart")
	}
	if restarted.Authenticated(sessionRequest(ordinary)) {
		t.Fatal("an ordinary session survived a restart")
	}
	if expired := rememberedGate(t, dir, now.Add(31*24*time.Hour)); expired.Authenticated(sessionRequest(remembered)) {
		t.Fatal("an expired remembered session was loaded")
	}
}

func TestRememberedSessionRevocationAndPasswordChangeLastAcrossRestart(t *testing.T) {
	dir, now := t.TempDir(), time.Unix(1_800_000_000, 0)
	gate := rememberedGate(t, dir, now)
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	first, _ := gate.LoginRemembered("admin", "correct-horse-battery-staple", true)
	second, _ := gate.LoginRemembered("admin", "correct-horse-battery-staple", true)
	var id string
	for _, s := range gate.Sessions(sessionRequest(second)) {
		if !s.Current {
			id = s.ID
		}
	}
	if id == "" || !gate.RevokeSession(id) {
		t.Fatal("remembered session was not revoked")
	}
	restarted := rememberedGate(t, dir, now)
	if restarted.Authenticated(sessionRequest(first)) || !restarted.Authenticated(sessionRequest(second)) {
		t.Fatal("revocation did not last across a restart")
	}
	if _, err := restarted.ChangePassword("correct-horse-battery-staple", "another-long-passphrase", sessionRequest(second)); err != nil {
		t.Fatal(err)
	}
	if again := rememberedGate(t, dir, now); again.Authenticated(sessionRequest(second)) {
		t.Fatal("a password change left a remembered session")
	}
}

func TestInvalidRememberedSessionsFileIsIgnoredAndReplaced(t *testing.T) {
	dir, now := t.TempDir(), time.Unix(1_800_000_000, 0)
	path := filepath.Join(dir, "admin.sessions.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	gate, err := NewGate(rememberedTestToken)
	if err != nil {
		t.Fatal(err)
	}
	gate.now = func() time.Time { return now }
	if err := gate.ConfigureCredentials(filepath.Join(dir, "admin.credentials.json")); err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureRememberedSessions(path); err == nil {
		t.Fatal("a broken file was accepted")
	}
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	token, err := gate.LoginRemembered("admin", "correct-horse-battery-staple", true)
	if err != nil {
		t.Fatal(err)
	}
	if !rememberedGate(t, dir, now).Authenticated(sessionRequest(token)) {
		t.Fatal("the broken file was not replaced")
	}
}
