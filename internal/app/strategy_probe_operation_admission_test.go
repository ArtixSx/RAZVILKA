package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestStrategyProbeMiddlewareRetainsOriginalExclusiveUntilCompletion(t *testing.T) {
	for _, path := range []string{"/api/v1/strategy-lab/candidates/candidate/probe", "/api/v1/strategy-lab/candidates/candidate/probe/", "/api/v1/strategy-lab/candidates/candidate/validate"} {
		t.Run(path, func(t *testing.T) {
			a := new(App)
			var complete func()
			handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				scope, ok := r.Context().Value(operationContextKey{}).(*operationScope)
				if !ok || scope.app != a || !scope.exclusive {
					t.Fatal("request did not receive original exclusive middleware admission")
				}
				owned, release, err := a.privateExclusiveOperation(r.Context())
				if err != nil {
					t.Fatal("managed handler could not retain its original operation", err)
				}
				complete = release
				if err := a.Operations.WithExclusiveContext(owned, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				if next, err := a.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
					if next != nil {
						next()
					}
					t.Fatal("probe shared actual exclusive owner", err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
			if response.Code != http.StatusNoContent || complete == nil {
				t.Fatal(response.Code, response.Body.String())
			}
			defer complete()
			if next, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
				if next != nil {
					next()
				}
				t.Fatal("HTTP return released unknown physical cleanup", err)
			}
			complete()
			next, err := a.Operations.Exclusive(context.Background())
			if err != nil {
				t.Fatal("known completion retained old operation", err)
			}
			next()
		})
	}
}

func TestStrategyProbeReadCannotBorrowExclusiveMiddlewareOwner(t *testing.T) {
	a := new(App)
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, release, err := a.privateExclusiveOperation(r.Context()); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			t.Fatal("read upgraded shared admission", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/strategy-lab/candidates/candidate/probe", nil))
	if w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
}
