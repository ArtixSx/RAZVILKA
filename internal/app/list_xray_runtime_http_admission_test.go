package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual middleware and actual Gate admission only. No runtime fixture or
// private copied Xray object may manufacture process/COMMON authority here.
func TestListXrayOrdinaryReadersRetainActualRequestAdmission(t *testing.T) {
	for _, path := range []string{"/api/v1/plan", "/api/v1/status", "/api/v1/service-control", "/api/v1/components"} {
		t.Run(path, func(t *testing.T) {
			a := &App{}
			var escaped context.Context
			visited := false
			handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				visited = true
				c, end, err := a.privateExclusiveOperation(r.Context())
				if err != nil {
					t.Fatal("ordinary reader cannot enter original retained observation", err)
				}
				defer end()
				escaped = c
				cleanup, err := a.Operations.ReviewExclusiveCleanup(c)
				if err != nil {
					t.Fatal("reader has no original operation", err)
				}
				finite, cancel := context.WithTimeout(c, time.Second)
				defer cancel()
				if err := cleanup.WithCurrent(finite, func() error { return nil }); err != nil || a.Operations.Snapshot().Active != 1 {
					t.Fatal("observation reentered admission", err)
				}
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
			if !visited || a.Operations.Snapshot().Active != 0 {
				t.Fatal("actual reader admission did not join")
			}
			if _, _, err := a.privateExclusiveOperation(escaped); !errors.Is(err, operationgate.ErrBusy) {
				t.Fatal("released reader revived original owner", err)
			}
		})
	}
}
