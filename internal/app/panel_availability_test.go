package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/security"
)

const panelTestToken = "panel-availability-test-token-0123456789"

func panelTestApp(t *testing.T) *App {
	t.Helper()
	gate, err := security.NewGate(panelTestToken)
	if err != nil {
		t.Fatal(err)
	}
	return &App{Security: gate}
}

func panelTestRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+panelTestToken)
	return r
}

// These integration tests require the complete repository/toolchain. The
// isolated Stage 1 package suite is NOT a substitute for executing them.
func TestPanelAvailabilityBypassesOnlyItsOwnMemoryEndpoint(t *testing.T) {
	a := panelTestApp(t)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	called := false
	h := a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, path := range []string{"/api/v1/panel/availability", "/api/v1/status", "/api/v1/services", "/api/v1/panel/availability/extra"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, panelTestRequest(http.MethodGet, path))
		if path == "/api/v1/panel/availability" {
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"busy"`) {
				t.Fatal(w.Code, w.Body.String())
			}
		} else if w.Code != 409 {
			t.Fatalf("%s bypassed admission: %d", path, w.Code)
		}
	}
	if called {
		t.Fatal("a Store-reading handler was invoked while exclusive admission was held")
	}
}

func TestPanelAvailabilityMethodsDoNotInterruptWorker(t *testing.T) {
	a := panelTestApp(t)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	h := a.operationMiddleware(http.NotFoundHandler())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, panelTestRequest(method, "/api/v1/panel/availability"))
		if w.Code != 405 || a.Operations.Snapshot().State != "busy" {
			t.Fatalf("invalid %s handling", method)
		}
	}
}

func TestPanelAvailabilityRealHTTPAuthAndAdmission(t *testing.T) {
	a := panelTestApp(t) // Deliberately no Store: this read must not need it.
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	request := func(method, path string, authenticated bool) (int, string) {
		t.Helper()
		body := `{}`
		if path == "/api/v1/service-control/runtime" {
			body = `{"action":"stop","confirm":"STOP_OWNED_ROUTES","expected_revision":1}`
		}
		r, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+panelTestToken)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(data)
	}
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.Fence()
			release()
		}
		before := a.Operations.Snapshot()
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			code, body := request(method, "/api/v1/panel/availability", false)
			if code != http.StatusUnauthorized || strings.Contains(body, "admission") {
				t.Fatalf("anonymous admission metadata: %d %s", code, body)
			}
		}
		code, body := request(http.MethodGet, "/api/v1/panel/availability", true)
		var result struct {
			Panel, Dataplane string
			Admission        struct{ State string }
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &result) != nil || result.Panel != "responding" || result.Dataplane != "not-checked" || result.Admission.State != before.State {
			t.Fatalf("invalid availability: %d %s", code, body)
		}
		code, body = request(http.MethodPost, "/api/v1/panel/availability", true)
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected mutation: %d %s", code, body)
		}
		// Stop cannot use panel availability to bypass recovery admission.
		code, body = request(http.MethodPost, "/api/v1/service-control/runtime", true)
		want := http.StatusConflict
		if fenced {
			want = http.StatusServiceUnavailable
		}
		if code != want {
			t.Fatalf("stop bypassed admission: %d %s", code, body)
		}
		// Cancel is memory-only and must never clear a cleanup/recovery fence.
		request(http.MethodDelete, "/api/v1/service-control/current", true)
		if after := a.Operations.Snapshot(); after != before {
			t.Fatalf("admission changed: %+v -> %+v", before, after)
		}
	}
}
