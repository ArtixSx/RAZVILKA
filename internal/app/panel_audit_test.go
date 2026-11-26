package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
)

func TestPanelAuditRealHTTPRemainsAvailableDuringApplyAndRecovery(t *testing.T) {
	a := panelTestApp(t) // No Store: admission-free handlers cannot read it.
	a.Audit = auditlog.New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err := a.Audit.Append(auditlog.Event{Action: "APPLY", Outcome: "failed"}); err != nil {
		t.Fatal(err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := http.Client{Timeout: time.Second}
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.Fence()
			release()
		}
		for _, auth := range []bool{false, true} {
			req, _ := http.NewRequest(http.MethodGet, server.URL+panelAuditPath+"?limit=1", nil)
			if auth {
				req.Header.Set("Authorization", "Bearer "+panelTestToken)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if auth {
				if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(string(data), `"memory_only":true`) || !strings.Contains(string(data), `"outcome":"failed"`) {
					t.Fatalf("%d %s", resp.StatusCode, data)
				}
			} else if resp.StatusCode != 401 || strings.Contains(string(data), "APPLY") {
				t.Fatalf("unauthorized history: %d %s", resp.StatusCode, data)
			}
		}
		w := httptest.NewRecorder()
		a.operationMiddleware(http.NotFoundHandler()).ServeHTTP(w, panelTestRequest(http.MethodDelete, panelAuditPath))
		if w.Code != 405 {
			t.Fatalf("accepted audit mutation: %d", w.Code)
		}
	}
}
