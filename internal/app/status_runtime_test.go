package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestStatusRejectsPastSuccessfulExecutionWithoutCurrentOwnedRuntime(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(t.TempDir())
	adapter := &serviceRuntimeAdapter{nodeApplyAdapter: &nodeApplyAdapter{}, name: "nfqws2"}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan, err := dataplane.BuildAt(dataplane.Input{
		Revision: store.Get().Revision,
		Routes:   []dataplane.Route{{ServiceID: "youtube", Resolved: "nfqws2"}},
		Engines:  []dataplane.Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}},
		Host:     dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"},
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	execution, err := manager.Apply(context.Background(), plan, store.ApplyDraftWithRollback)
	if err != nil || execution.State != "committed" {
		t.Fatalf("fixture transaction failed: %+v %v", execution, err)
	}
	before := store.Get()
	calls := append([]string{}, adapter.calls...)
	a := &App{Store: store, Catalog: catalog.Catalog{}, Dataplane: manager, Start: time.Now()}
	response := httptest.NewRecorder()
	a.status(response, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var result struct {
		Live     bool   `json:"live_active"`
		State    string `json:"dataplane_state"`
		Recovery string `json:"dataplane_recovery_state"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.Live || result.State != "committed" || result.Recovery != "runtime-unverified" {
		t.Fatalf("past success became present runtime proof: HTTP%d %+v", response.Code, result)
	}
	if !reflect.DeepEqual(before, store.Get()) || !reflect.DeepEqual(calls, adapter.calls) {
		t.Fatal("status observation changed settings or invoked a runtime transaction")
	}
}
