package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestManagedStrategyHTTPMissingInstalledReceiptNeverFallsBackToLibraryValidator(t *testing.T) {
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
	a.Components = components.New()
	a.Components.StateDir = t.TempDir()
	observer := &strategyOriginalAdmissionObserver{app: a}
	manager.Validator = observer
	before, err := os.ReadFile(manager.Path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, data := componentHTTP(t, server, "POST", "/api/v1/strategy-lab/candidates/"+candidate.ID+"/validate", map[string]any{}, componentRecoveryToken, server.URL)
	after, readErr := os.ReadFile(manager.Path)
	if status != 503 || !bytes.Contains(data, []byte("MANAGED_NFQWS_SOURCE_UNAVAILABLE")) || observer.calls != 0 || readErr != nil || !bytes.Equal(before, after) {
		t.Fatal("missing installed bundle reached legacy validation or changed source", status, string(data), observer.calls, readErr)
	}
	if a.Operations.Snapshot().Active != 0 || a.strategyCompatibilityPending() {
		t.Fatal("pre-admission missing source retained an invocation")
	}
}

func TestManagedStrategyUnknownKeepsActualRequestBorrowAndReadOnlyAuthenticatedSnapshot(t *testing.T) {
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
	var originalRelease func()
	// This negative model retains a genuine request admission. Its zero opaque
	// completion cannot represent a joined producer or authorize retirement.
	begin := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, release, err := a.privateExclusiveOperation(r.Context())
		if err != nil {
			t.Fatal(err)
		}
		originalRelease = release
		a.retainStrategyCompatibility(&strategyCompatibilityRetention{manager: manager, completion: &strategylab.ManagedCompatibilityCompletion{}, release: release})
	}))
	begin.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/strategy-lab/candidates/"+candidate.ID+"/validate", nil))
	defer originalRelease() // test teardown only; no production proof or unlock.
	if a.Operations.Snapshot().Active != 1 {
		t.Fatal("request close released original held operation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.strategyCompatibility.pending.completion.RetireKnown(ctx); err == nil || a.Operations.Snapshot().Active != 1 {
		t.Fatal("zero completion retired original resources", err)
	}
	if err := a.WaitManagedStrategyCompatibility(ctx); err == nil || a.Operations.Snapshot().Active != 1 {
		t.Fatal("shutdown cleanup manufactured completion or released original borrow", err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, data := componentHTTP(t, server, "GET", "/api/v1/strategy-lab", nil, componentRecoveryToken, server.URL)
	var snapshot strategylab.Snapshot
	if status != 200 || json.Unmarshal(data, &snapshot) != nil || !snapshot.QuiescenceUnknown || len(snapshot.Candidates) != 1 {
		t.Fatal("original unknown blocked readonly saved snapshot", status, string(data))
	}
	if status, _ := componentHTTP(t, server, "GET", "/api/v1/strategy-lab", nil, "", server.URL); status == 200 {
		t.Fatal("private unknown snapshot bypassed authentication")
	}
	for _, path := range []string{"/api/v1/strategy-lab/candidates/" + candidate.ID + "/validate", "/api/v1/strategy-lab/candidates", "/api/v1/apply"} {
		status, data := componentHTTP(t, server, "POST", path, map[string]any{}, componentRecoveryToken, server.URL)
		if status != 503 || !bytes.Contains(data, []byte("STRATEGY_COMPATIBILITY_RECOVERY_REQUIRED")) {
			t.Fatal("unknown admitted a new mutation", path, status, string(data))
		}
	}
	if observer.calls != 0 || a.Operations.Snapshot().Active != 1 {
		t.Fatal("readonly GET, refusal or elapsed cleanup context released/retried original operation")
	}
}
