package security

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
