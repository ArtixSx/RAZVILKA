package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Real HTTP, Gate, Store and journal. No component process or network path is
// started: concurrent panel reads must not pretend to be recovery writers.
func TestComponentRecoveryIdleReadOverlapsOtherPanelRead(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	held, err := a.Operations.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	status, wire := componentHTTP(t, server, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, server.URL)
	var response struct {
		Required     bool   `json:"recovery_required"`
		Revision     uint64 `json:"revision"`
		Capabilities struct {
			Actions []string `json:"available_actions"`
		} `json:"capabilities"`
	}
	if status != http.StatusOK || json.Unmarshal(wire, &response) != nil || response.Required || response.Revision != a.Store.Get().Revision || len(response.Capabilities.Actions) != 0 {
		t.Fatalf("ordinary read did not return a clean, non-writing journal: %d %s", status, wire)
	}
	if a.managedNFQBundle.control != nil {
		t.Fatal("ordinary read retained a control capability")
	}
	held()
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("journal read leaked admission", err)
	} else {
		release()
	}
}

func TestComponentRecoveryReadKeepsExclusiveAndCorruptJournalFences(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	held, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	status, wire := componentHTTP(t, server, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, server.URL)
	var failure struct {
		Code string `json:"code"`
	}
	if status != http.StatusConflict || json.Unmarshal(wire, &failure) != nil || failure.Code != "RESTORE_OPERATION_BUSY" {
		t.Fatalf("read bypassed an exclusive operation: %d %s", status, wire)
	}
	held()
	directory := filepath.Join(a.Components.StateDir, "update-journal")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "current.json"), []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	status, wire = componentHTTP(t, server, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, server.URL)
	if status != http.StatusServiceUnavailable || json.Unmarshal(wire, &failure) != nil || failure.Code != "COMPONENT_JOURNAL_UNAVAILABLE" || !a.PendingComponentRecovery() {
		t.Fatalf("read interpreted an unknown journal as clean: %d %s", status, wire)
	}
	if a.managedNFQBundle.control != nil {
		t.Fatal("corrupt journal acquired a control capability")
	}
}
