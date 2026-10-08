package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

type strategyOriginalAdmissionObserver struct {
	app     *App
	calls   int
	ctx     context.Context
	current error
	bounded bool
}

func (v *strategyOriginalAdmissionObserver) Validate(ctx context.Context, args []string) strategylab.Validation {
	v.calls++
	v.ctx = ctx
	deadline, bounded := ctx.Deadline()
	v.bounded = bounded && time.Until(deadline) > 0 && time.Until(deadline) <= 10*time.Second
	v.current = v.app.Operations.WithExclusiveContext(ctx, func() error { return nil })
	// This observer launches nothing and never manufactures a native proof.
	return strategylab.Validation{Code: "SOURCE_REVIEW_REQUIRED", Arguments: args}
}

func TestStrategyValidationHTTPRetainsOriginalExclusiveOperationWithoutGrantingRuntime(t *testing.T) {
	a, _ := defaultConsentHTTPFixture(t)
	manager, err := strategylab.New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := manager.AddCandidate("tcp-tls", "review", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	a.StrategyLab = manager
	observer := &strategyOriginalAdmissionObserver{app: a}
	manager.Validator = observer
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	path := "/api/v1/strategy-lab/candidates/" + candidate.ID + "/validate"
	before, sourceBefore := a.Store.Get(), manager.Snapshot()
	busyRelease, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status, _ := componentHTTP(t, server, "POST", path, map[string]any{}, componentRecoveryToken, server.URL)
	busyRelease()
	if status != 409 || observer.calls != 0 || !reflect.DeepEqual(manager.Snapshot(), sourceBefore) {
		t.Fatal("busy request reached validation or changed its source", status, observer.calls)
	}
	if status, data := componentHTTP(t, server, "POST", path, map[string]any{}, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal("actual admitted validation request", status, string(data))
	}
	if observer.calls != 1 || !observer.bounded || observer.current != nil {
		t.Fatal("validation received a shared/raw operation", observer.calls, observer.bounded, observer.current)
	}
	if err := a.Operations.WithExclusiveContext(observer.ctx, func() error { t.Fatal("released request revived"); return nil }); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("retained context revived original admission", err)
	}
	if !reflect.DeepEqual(a.Store.Get(), before) || a.Store.Get().DefaultRouteConsent != nil || a.Store.Get().NetworkPolicy != nil || manager.Snapshot().Candidates[0].Validation.Native {
		t.Fatal("compatibility request created list/provider/client permission")
	}
}
