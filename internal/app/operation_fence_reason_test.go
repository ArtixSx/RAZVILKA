package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFenceReasonSelectsRecoveryCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fence func(*App)
		code  string
	}{
		{"private-restore", func(a *App) { a.Operations.Fence() }, "PRIVATE_BACKUP_RECOVERY_REQUIRED"},
		{"network-journal", func(a *App) { a.Operations.FenceJournal() }, "DATAPLANE_RECOVERY_REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{}
			tc.fence(a)
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
			var body struct {
				Code             string `json:"code"`
				RecoveryRequired bool   `json:"recovery_required"`
				NotStarted       bool   `json:"not_started"`
				Name             string `json:"name"`
			}
			if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != tc.code || !body.RecoveryRequired || !body.NotStarted || body.Name != "RAZVILKA" {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
