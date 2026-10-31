package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// The controlled guard models a durable recovery read that has not returned.
// Actual HTTP authentication and panel handlers still run; the test does not
// claim a latency bound for router storage, runtime admission or service probes.
func TestPanelReadsRemainAvailableDuringDurableAdmissionGuard(t *testing.T) {
	a := savedPanelFixture(t)
	var block atomic.Bool
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	if err := a.Operations.SetGuard(func(context.Context) error {
		if !block.Load() {
			return nil
		}
		close(entered)
		<-resume
		return operationgate.ErrRecovery
	}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-panelSnapshotLifetime - time.Minute)
	if !a.publishPanelSnapshot(context.Background(), strings.Repeat("a", 32), old) {
		t.Fatal("could not prepare saved settings")
	}
	ctx, update := operationgate.WithProgress(operationgate.WithLabel(context.Background(), "Автопилот"), "autonomy")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	update("checking", "telegram")
	before := a.Operations.Snapshot()
	// A memory-only panel read must not fall back to live configuration.
	a.Store = nil
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	block.Store(true)
	var attemptErr error
	go func() {
		defer close(done)
		release, err := a.Operations.Enter(context.Background())
		attemptErr = err
		if release != nil {
			release()
		}
	}()
	// Drain a failed pre-fix HTTP request before shutting down its server.
	defer func() {
		resumeOnce.Do(func() { close(resume) })
		awaitOperation(t, done)
	}()
	awaitOperation(t, entered)
	cancel()
	update("cleanup", "telegram")
	for _, path := range []string{"/api/v1/panel/availability", panelSnapshotPath} {
		for _, authenticated := range []bool{false, true} {
			request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if authenticated {
				request.Header.Set("Authorization", "Bearer "+panelTestToken)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("panel HTTP waited for durable guard (%s): %v", path, err)
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !authenticated {
				if response.StatusCode != http.StatusUnauthorized || strings.Contains(string(body), "progress") {
					t.Fatalf("anonymous progress disclosure: %d %s", response.StatusCode, body)
				}
				continue
			}
			var value struct {
				Dataplane string                 `json:"dataplane"`
				Admission operationgate.Snapshot `json:"admission"`
			}
			if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || json.Unmarshal(body, &value) != nil || value.Dataplane != "not-checked" || value.Admission.State != "busy" || value.Admission.Active != 1 || value.Admission.Progress == nil || value.Admission.Progress.ID != before.Progress.ID || value.Admission.Progress.Phase != "cleanup" {
				t.Fatalf("invalid live progress during guard (%s): %d %s", path, response.StatusCode, body)
			}
			if path == panelSnapshotPath {
				var saved panelSnapshotResponse
				if json.Unmarshal(body, &saved) != nil || saved.State != "expired" || len(saved.Data) != 0 || saved.Revision != 1 || saved.GeneratedAt == nil || !saved.GeneratedAt.Equal(old) {
					t.Fatalf("progress renewed expired configuration evidence: %s", body)
				}
			}
		}
	}
	select {
	case <-done:
		t.Fatal("panel read allowed a pending admission to complete")
	default:
	}
	resumeOnce.Do(func() { close(resume) })
	awaitOperation(t, done)
	if !errors.Is(attemptErr, operationgate.ErrRecovery) {
		t.Fatalf("panel observation changed durable refusal: %v", attemptErr)
	}
	if after := a.Operations.Snapshot(); after.Active != 1 || after.Progress == nil || after.Progress.ID != before.Progress.ID {
		t.Fatalf("guard refusal or panel observation released unfinished cleanup: %+v", after)
	}
	release()
	if after := a.Operations.Snapshot(); after.State != "idle" || after.Progress != nil {
		t.Fatalf("actual owner release left stale presentation: %+v", after)
	}
}
