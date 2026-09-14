package security

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func passwordFixture(t *testing.T) (*Gate, string) {
	t.Helper()
	gate, err := NewGate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := gate.ConfigureCredentials(path); err != nil {
		t.Fatal(err)
	}
	return gate, path
}

func passwordSessionRequest(session string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://router.local/api/v1/system", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	return request
}

func setFixturePassword(gate *Gate, operation, password string) (string, error) {
	switch operation {
	case "setup":
		return gate.Setup("admin", password)
	case "change":
		return gate.ChangePassword("previous-fixture-password", password, nil)
	case "recover":
		request := httptest.NewRequest(http.MethodPost, "http://router.local/api/v1/auth/recover", nil)
		request.Header.Set("Authorization", "Bearer "+testToken)
		return gate.RecoverPassword("admin", password, request)
	default:
		panic("unknown fixture operation")
	}
}

func TestPasswordsAcceptExactShortAndWhitespaceValues(t *testing.T) {
	for _, operation := range []string{"setup", "change", "recover"} {
		for _, value := range []struct{ name, password string }{
			{"one-character", "x"},
			{"whitespace", "  "},
			{"unicode", "я"},
		} {
			t.Run(operation+"/"+value.name, func(t *testing.T) {
				gate, path := passwordFixture(t)
				var priorSession string
				if operation != "setup" {
					var err error
					priorSession, err = gate.Setup("admin", "previous-fixture-password")
					if err != nil {
						t.Fatal(err)
					}
				}
				session, err := setFixturePassword(gate, operation, value.password)
				if err != nil || session == "" || !gate.Authenticated(passwordSessionRequest(session)) {
					t.Fatalf("nonempty password was not accepted: %v", err)
				}
				if priorSession != "" && gate.Authenticated(passwordSessionRequest(priorSession)) {
					t.Fatal("replacing a short password must still revoke prior sessions")
				}
				reloaded, err := NewGate(testToken)
				if err != nil {
					t.Fatal(err)
				}
				if err := reloaded.ConfigureCredentials(path); err != nil {
					t.Fatal(err)
				}
				if reloaded.Authenticated(passwordSessionRequest(session)) {
					t.Fatal("a session survived process-equivalent reload")
				}
				if _, err := reloaded.Login("admin", value.password); err != nil {
					t.Fatalf("persisted nonempty password cannot log in: %v", err)
				}
				if _, err := reloaded.Login("admin", value.password+" "); err == nil {
					t.Fatal("password whitespace was normalized instead of matched exactly")
				}
			})
		}
	}
}

func TestEmptyAndOversizedPasswordsDoNotChangeCredentialsOrSessions(t *testing.T) {
	for _, operation := range []string{"setup", "change", "recover"} {
		t.Run(operation, func(t *testing.T) {
			gate, path := passwordFixture(t)
			var priorSession string
			var before []byte
			if operation != "setup" {
				var err error
				priorSession, err = gate.Setup("admin", "previous-fixture-password")
				if err != nil {
					t.Fatal(err)
				}
				before, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, invalid := range []string{"", strings.Repeat("x", 257), strings.Repeat("я", 129)} {
				if session, err := setFixturePassword(gate, operation, invalid); err == nil || session != "" {
					t.Fatal("empty/oversized password was accepted")
				}
				after, err := os.ReadFile(path)
				if operation == "setup" {
					if !errors.Is(err, os.ErrNotExist) || !gate.SetupRequired() || len(gate.Sessions(nil)) != 0 {
						t.Fatal("rejected setup created an account or session")
					}
				} else if err != nil || !bytes.Equal(before, after) || !gate.Authenticated(passwordSessionRequest(priorSession)) {
					t.Fatal("rejected replacement changed credentials or revoked the current session")
				}
			}
		})
	}
}

func TestPasswordUpperBoundCountsUTF8BytesWithoutCompositionRules(t *testing.T) {
	for _, password := range []string{strings.Repeat("x", 256), strings.Repeat("я", 128)} {
		gate, path := passwordFixture(t)
		if _, err := gate.Setup("admin", password); err != nil {
			t.Fatalf("256-byte password rejected: %v", err)
		}
		reloaded, err := NewGate(testToken)
		if err != nil {
			t.Fatal(err)
		}
		if err := reloaded.ConfigureCredentials(path); err != nil {
			t.Fatal(err)
		}
		if _, err := reloaded.Login("admin", password); err != nil {
			t.Fatalf("256-byte persisted password cannot log in: %v", err)
		}
	}
}
