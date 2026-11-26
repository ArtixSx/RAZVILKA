package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestScopedRuntimeOperationRetainsSameActualAdmissionAcrossOuterClose(t *testing.T) {
	a, foreign := &App{}, &App{}
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, closeOuter, err := a.scopedRuntimeOperation(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOuter()
	borrowed, closeBorrowed, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBorrowed()
	if a.Operations.Snapshot().Active != 1 || a.Operations.WithExclusiveContext(borrowed, func() error { return nil }) != nil {
		t.Fatal("runtime borrow acquired a second owner or lost actual admission")
	}
	if err := foreign.Operations.WithExclusiveContext(borrowed, func() error { t.Fatal("foreign callback"); return nil }); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("foreign App adopted runtime context", err)
	}
	closeOuter()
	if a.Operations.Snapshot().Active != 1 {
		t.Fatal("outer return released retained cleanup admission")
	}
	if _, _, err := a.privateExclusiveOperation(ctx); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("returned runtime scope borrowed again", err)
	}
	if err := a.Operations.WithExclusiveContext(borrowed, func() error { return nil }); err != nil {
		t.Fatal("original retained work lost its still-live caller", err)
	}
	closeBorrowed()
	closeBorrowed()
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("joined cleanup failed to release original owner")
	}
	if err := a.Operations.WithExclusiveContext(borrowed, func() error { t.Fatal("released callback"); return nil }); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("released runtime context revived", err)
	}
}

func TestHTTPExclusiveContextBelongsToActualRequest(t *testing.T) {
	a := &App{}
	var retained context.Context
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		retained = r.Context()
		ctx, release, err := a.privateExclusiveOperation(r.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.privateExclusiveOperation(ctx); !errors.Is(err, operationgate.ErrBusy) {
			t.Fatal("double borrow", err)
		}
		if a.Operations.Snapshot().Active != 1 {
			t.Fatal("nested request admission")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/apply", nil))
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("outer request retained")
	}
	if _, _, err := a.privateExclusiveOperation(retained); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("expired request scope", err)
	}
}

func TestHTTPSharedContextCannotBecomeExclusiveAuthority(t *testing.T) {
	a := &App{}
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.Operations.WithExclusiveContext(r.Context(), func() error { t.Fatal("shared use"); return nil }); !errors.Is(err, operationgate.ErrBusy) {
			t.Fatal(err)
		}
		if _, _, err := a.privateExclusiveOperation(r.Context()); !errors.Is(err, operationgate.ErrBusy) {
			t.Fatal("shared upgrade", err)
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/services", nil))
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("shared request retained")
	}
}

func TestHTTPExclusiveBorrowRetainsAdmissionUntilCleanup(t *testing.T) {
	a := &App{}
	var cleanup func()
	var ctx context.Context
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx, cleanup, err = a.privateExclusiveOperation(r.Context())
		if err != nil {
			t.Fatal(err)
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/apply", nil))
	if a.Operations.Snapshot().Active != 1 {
		t.Fatal("request close released live owner")
	}
	if _, _, err := a.privateExclusiveOperation(ctx); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("expired scope borrowed again", err)
	}
	cleanup()
	cleanup()
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("cleanup did not release")
	}
}

func TestInternalExclusiveContextRejectsForeignAppAndCancellation(t *testing.T) {
	a, other := &App{}, &App{}
	raw, cancel := context.WithCancel(context.Background())
	ctx, release, err := a.privateExclusiveOperation(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := other.Operations.WithExclusiveContext(ctx, func() error { t.Fatal("foreign owner"); return nil }); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal(err)
	}
	cancel()
	if err := a.Operations.WithExclusiveContext(context.WithoutCancel(ctx), func() error { t.Fatal("canceled owner"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if a.Operations.Snapshot().Active != 1 {
		t.Fatal("cancellation released work before cleanup")
	}
}

func TestDefaultExecutorBorrowsActualHTTPExclusiveOperation(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	e, snapshot, adapter := defaultRouteExecutorFixture(t)
	routes := defaultRouteListedRoutes()
	// Save and load a CIDR-only test catalogue definition; this operation test
	// uses no domain projection and does not claim native packet success.
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	image, err := json.Marshal(catalog.Catalog{Services: []catalog.Service{{
		ID: routes[0].ServiceID, Name: routes[0].ServiceName, Category: "Test",
		CIDRs: routes[0].CIDRs, Strategy: []string{routes[0].Selected},
		ProbeURL: snapshot.Paths[routes[0].ServiceID].ProbeURL,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, image, 0o600); err != nil {
		t.Fatal(err)
	}
	e.app.Catalog, err = catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	service := e.app.Catalog.Services[0]
	routes[0].ServiceName, routes[0].CIDRs, routes[0].ProbeURL = service.Name, service.CIDRs, service.ProbeURL
	observe := e.deps.Observe
	e.deps.Observe = func(ctx context.Context) (DefaultRouteSnapshot, error) {
		if err := e.app.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			t.Fatal("observer received no original admission", err)
		}
		return observe(ctx)
	}
	handler := e.app.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		review, err := e.Review(r.Context(), routes)
		if err != nil {
			t.Fatal("review reentered request gate", err)
		}
		if len(review.Plan().Routes) == 0 {
			t.Fatal("operation test did not review the listed CIDR route")
		}
		execution, err := e.Execute(r.Context(), review, review.Digest())
		if err != nil || execution.State != "committed" {
			t.Fatal("execute reentered request gate", execution.State, err)
		}
		if e.app.Operations.Snapshot().Active != 1 {
			t.Fatal("executor released outer HTTP admission")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/apply", nil))
	if !adapter.live || e.app.Operations.Snapshot().Active != 0 {
		t.Fatal("actual executor/app request did not finish")
	}
}
