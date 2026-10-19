package updatecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOfficialReleaseComparison(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.10.0","html_url":"https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.10.0","published_at":"2026-08-14T10:00:00Z"}`))
	}))
	defer server.Close()
	manager := New("0.9.0")
	manager.Endpoint, manager.Client = server.URL, server.Client()
	result := manager.Check(context.Background(), true)
	if result.State != "update" || !result.UpdateAvailable || result.LatestVersion != "0.10.0" {
		t.Fatalf("unexpected update result: %+v", result)
	}
}

func TestRejectsPrereleaseAndInvalidLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","html_url":"https://evil.example/release","prerelease":true}`))
	}))
	defer server.Close()
	manager := New("0.9.0")
	manager.Endpoint, manager.Client = server.URL, server.Client()
	result := manager.Check(context.Background(), true)
	if result.State != "check-failed" || result.Error == "" {
		t.Fatalf("untrusted release was accepted: %+v", result)
	}
}

func TestNormalizesHistoricalOfficialTagSuffix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.5.1-security-gate","html_url":"https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.5.1-security-gate"}`))
	}))
	defer server.Close()
	manager := New("0.9.0")
	manager.Endpoint, manager.Client = server.URL, server.Client()
	result := manager.Check(context.Background(), true)
	if result.State != "ahead" || result.LatestVersion != "0.5.1" || result.UpdateAvailable {
		t.Fatalf("unexpected historical tag result: %+v", result)
	}
}

func TestDevelopmentBuildIsOlderThanMatchingStableRelease(t *testing.T) {
	if compareVersions("0.11.0-dev", "0.11.0") >= 0 {
		t.Fatal("development build must be considered older than the matching stable release")
	}
	if compareVersions("0.11.0", "0.11.0-dev") <= 0 {
		t.Fatal("stable release must be considered newer than its development build")
	}
}

// An installed 0.20+ updates only through the journaled self-update; the
// installer refuses it. The check result must not suggest piping an unpinned
// branch bootstrap into a shell, on success or on failure.
func TestCheckResultSuggestsNoUnpinnedInstallCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.10.0","html_url":"https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.10.0"}`))
	}))
	defer server.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer failing.Close()
	for _, endpoint := range []*httptest.Server{server, failing} {
		manager := New("0.9.0")
		manager.Endpoint, manager.Client = endpoint.URL, endpoint.Client()
		encoded, err := json.Marshal(manager.Check(context.Background(), true))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"install_command", "bootstrap.sh", "| sh"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("update check result suggests an installer command (%q): %s", forbidden, encoded)
			}
		}
	}
}
