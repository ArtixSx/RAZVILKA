package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdefghijklmnopqrstuvwxyz-TEST"

func TestGateProtectsOnlyMutations(t *testing.T) {
	gate, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := gate.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	read := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/status", nil)
	read.Host = "router.local"
	readResult := httptest.NewRecorder()
	handler.ServeHTTP(readResult, read)
	if readResult.Code != http.StatusNoContent || !called {
		t.Fatalf("read request = %d, called=%v", readResult.Code, called)
	}

	tests := []struct {
		name        string
		token       string
		origin      string
		contentType string
		want        int
	}{
		{name: "missing token", origin: "http://router.local", contentType: "application/json", want: http.StatusUnauthorized},
		{name: "wrong token", token: "wrong-wrong-wrong-wrong-wrong-wrong", origin: "http://router.local", contentType: "application/json", want: http.StatusUnauthorized},
		{name: "foreign origin", token: testToken, origin: "http://attacker.invalid", contentType: "application/json", want: http.StatusForbidden},
		{name: "wrong content type", token: testToken, origin: "http://router.local", contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "authenticated", token: testToken, origin: "http://router.local", contentType: "application/json; charset=utf-8", want: http.StatusNoContent},
		{name: "authenticated cli", token: testToken, contentType: "application/json", want: http.StatusNoContent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodPost, "http://router.local/api/v1/apply", nil)
			req.Host = "router.local"
			req.Header.Set("Content-Type", tc.contentType)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, req)
			if result.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", result.Code, tc.want, result.Body.String())
			}
			if called != (tc.want == http.StatusNoContent) {
				t.Fatalf("called=%v for status %d", called, tc.want)
			}
		})
	}
}

func TestLoadOrCreateTokenIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "admin.token")
	firstGate, first, created, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created || firstGate == nil || len(first) < minimumTokenLength {
		t.Fatalf("created=%v gate=%v token length=%d", created, firstGate != nil, len(first))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("token permissions are too broad: %o", info.Mode().Perm())
	}

	secondGate, second, created, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if created || secondGate == nil || second != first {
		t.Fatalf("second load changed token: created=%v equal=%v", created, second == first)
	}
}

func TestNewGateRejectsWeakToken(t *testing.T) {
	if _, err := NewGate("too-short"); err == nil {
		t.Fatal("expected weak token to be rejected")
	}
}

func TestLoadRejectsTokenSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privilege-dependent on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "admin.token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadOrCreateToken(link); err == nil {
		t.Fatal("expected token symlink to be rejected")
	}
}

func TestFirstRunSetupAndPasswordSession(t *testing.T) {
	gate, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "admin.credentials.json")
	if err := gate.ConfigureCredentials(path); err != nil {
		t.Fatal(err)
	}
	if !gate.SetupRequired() {
		t.Fatal("fresh gate must require setup")
	}
	session, err := gate.Setup("admin", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	if session == "" || gate.SetupRequired() {
		t.Fatal("setup did not create an account/session")
	}
	if _, err := gate.Setup("other", "correct-horse-battery-staple"); err == nil {
		t.Fatal("second setup accepted")
	}
	if _, err := gate.Login("admin", "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	loginSession, err := gate.Login("admin", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/system", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: loginSession})
	if !gate.Authenticated(req) {
		t.Fatal("session cookie not authenticated")
	}
	gate.Logout(req)
	if gate.Authenticated(req) {
		t.Fatal("logged-out session still authenticated")
	}

	reloaded, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.ConfigureCredentials(path); err != nil {
		t.Fatal(err)
	}
	if reloaded.SetupRequired() || reloaded.Username() != "admin" {
		t.Fatal("credentials were not persisted")
	}
}

func TestConfiguredGateProtectsReadAPI(t *testing.T) {
	gate, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	handler := gate.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	private := httptest.NewRecorder()
	handler.ServeHTTP(private, httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/system", nil))
	if private.Code != http.StatusUnauthorized {
		t.Fatalf("private read=%d", private.Code)
	}
	public := httptest.NewRecorder()
	handler.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/status", nil))
	if public.Code != http.StatusNoContent {
		t.Fatalf("public status=%d", public.Code)
	}
}

func TestLoginRateLimitIsPerClientAndExpires(t *testing.T) {
	gate, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	gate.now = func() time.Time { return now }
	gate.loginMax = 2
	gate.loginLockout = 30 * time.Second
	request := httptest.NewRequest(http.MethodPost, "http://router.local/api/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.10:12345"
	for i := 0; i < 2; i++ {
		if _, err := gate.Login("admin", "wrong-password", request); err == nil {
			t.Fatal("wrong password accepted")
		}
	}
	if _, err := gate.Login("admin", "correct-horse-battery-staple", request); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("rate-limit error = %v", err)
	}
	now = now.Add(31 * time.Second)
	if _, err := gate.Login("admin", "correct-horse-battery-staple", request); err != nil {
		t.Fatalf("login after lockout: %v", err)
	}
}

func TestPasswordChangeAndSessionManagement(t *testing.T) {
	gate, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	first, err := gate.Setup("admin", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "http://router.local/api/v1/auth/login", nil)
	loginRequest.RemoteAddr = "192.0.2.11:54321"
	loginRequest.Header.Set("User-Agent", "RAZVILKA test browser")
	second, err := gate.Login("admin", "correct-horse-battery-staple", loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	current := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/auth/sessions", nil)
	current.AddCookie(&http.Cookie{Name: sessionCookie, Value: second})
	sessions := gate.Sessions(current)
	if len(sessions) != 2 {
		t.Fatalf("sessions=%d, want 2", len(sessions))
	}
	currentCount := 0
	for _, session := range sessions {
		if session.Current {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Fatalf("current sessions=%d", currentCount)
	}
	if removed := gate.RevokeOtherSessions(current); removed != 1 || len(gate.Sessions(current)) != 1 {
		t.Fatalf("removed=%d sessions=%d", removed, len(gate.Sessions(current)))
	}
	if _, err := gate.ChangePassword("wrong-password", "new-correct-horse-battery", current); err == nil {
		t.Fatal("password changed with wrong current password")
	}
	third, err := gate.ChangePassword("correct-horse-battery-staple", "new-correct-horse-battery", current)
	if err != nil {
		t.Fatal(err)
	}
	old := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/system", nil)
	old.AddCookie(&http.Cookie{Name: sessionCookie, Value: second})
	if gate.Authenticated(old) {
		t.Fatal("old session survived password change")
	}
	newRequest := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/system", nil)
	newRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: third})
	if !gate.Authenticated(newRequest) {
		t.Fatal("new session is not authenticated")
	}
	if _, err := gate.Login("admin", "correct-horse-battery-staple"); err == nil {
		t.Fatal("old password still works")
	}
	if _, err := gate.Login("admin", "new-correct-horse-battery"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
	_ = first
}

func TestRecoveryPasswordAndKeyRotation(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	gate, recoveryKey, _, err := LoadOrCreateToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureCredentials(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	recoveryRequest := httptest.NewRequest(http.MethodPost, "http://router.local/api/v1/auth/recover", nil)
	recoveryRequest.Header.Set("Authorization", "Bearer "+recoveryKey)
	session, err := gate.RecoverPassword("owner", "new-correct-horse-battery", recoveryRequest)
	if err != nil || session == "" {
		t.Fatalf("recover password: session=%q err=%v", session, err)
	}
	if _, err := gate.Login("admin", "correct-horse-battery-staple"); err == nil {
		t.Fatal("old credentials survived recovery")
	}
	if _, err := gate.Login("owner", "new-correct-horse-battery"); err != nil {
		t.Fatalf("recovered credentials: %v", err)
	}
	rotated, err := gate.RotateRecoveryToken("new-correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if rotated == recoveryKey || len(rotated) < minimumTokenLength {
		t.Fatal("recovery key was not rotated")
	}
	if gate.RecoveryAuthenticated(recoveryRequest) {
		t.Fatal("old recovery key remained valid")
	}
	newRequest := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/status", nil)
	newRequest.Header.Set("Authorization", "Bearer "+rotated)
	if !gate.RecoveryAuthenticated(newRequest) {
		t.Fatal("new recovery key is not valid")
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil || strings.TrimSpace(string(data)) != rotated {
		t.Fatalf("rotated key was not persisted: %v", err)
	}
}
