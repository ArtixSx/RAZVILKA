package app

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/telemetry"
)

func TestConnectionStreamPrivateBeforeSetup(t *testing.T) {
	a := panelTestApp(t)
	a.Telemetry = telemetry.NewStore()
	a.Telemetry.Upsert(telemetry.Connection{ID: "private-row"})
	if err := a.Security.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/connections/stream", nil))
	if w.Code != 401 || strings.Contains(w.Body.String(), "private-row") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestConnectionStreamStopsAfterSessionRevocationWhileGateBusy(t *testing.T) {
	a := panelTestApp(t)
	a.Telemetry = telemetry.NewStore()
	a.Telemetry.Upsert(telemetry.Connection{ID: "before-logout"})
	if err := a.Security.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	session, err := a.Security.Setup("admin", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	a.Operations.Fence()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+"/api/v1/connections/stream", nil)
	cookies := httptest.NewRecorder()
	security.SetSessionCookie(cookies, req, session)
	req.AddCookie(cookies.Result().Cookies()[0])
	client := server.Client()
	client.Timeout = 3 * time.Second
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal(response.Status)
	}
	reader := bufio.NewReader(response.Body)
	var first strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		first.WriteString(line)
		if line == "\n" {
			break
		}
	}
	if !strings.Contains(first.String(), "before-logout") {
		t.Fatal("initial observation missing")
	}
	a.Security.Logout(req)
	a.Telemetry.Upsert(telemetry.Connection{ID: "after-logout"})
	remaining, err := io.ReadAll(reader)
	if err != nil || strings.Contains(string(remaining), "after-logout") {
		t.Fatal("revoked session retained private stream", err, string(remaining))
	}
	if !a.Operations.Snapshot().Exclusive || !a.Operations.Snapshot().Fenced {
		t.Fatal("stream altered admission")
	}
}
