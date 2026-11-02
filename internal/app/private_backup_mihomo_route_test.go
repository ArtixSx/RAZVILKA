package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

func TestPrivateBackupMihomoSelectionHTTPImportReloadStaysDraft(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	source := privateRestoreNodeApp(t, filepath.Join(t.TempDir(), "source"))
	const uri = "vless://123e4567-e89b-12d3-a456-426614174000@backup-node.example:443?security=tls&sni=backup-node.example&type=tcp"
	if _, err := source.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, uri, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.Nodes.Snapshot(ctx, now)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("source node", err)
	}
	nodeID := snapshot.Nodes[0].ID
	selection := config.ServiceState{Enabled: true, Route: "mihomo:" + nodeID, Mode: "mihomo:" + nodeID, Sources: []string{"192.168.1.42/32", "192.168.1.64/27"}}
	if err := source.Store.UpdateService("youtube", selection); err != nil {
		t.Fatal(err)
	}
	// All allowlisted config exports are local validated fixture drafts.
	stagePrivateBackupExportFixture(t, source)
	exported := requestPrivateBackupExport(source)
	var envelope privatebackup.Envelope
	if exported.Code != http.StatusOK || json.Unmarshal(exported.Body.Bytes(), &envelope) != nil || strings.Contains(exported.Body.String(), "backup-node.example") || strings.Contains(exported.Body.String(), selection.Route) {
		t.Fatal("encrypted HTTP export", exported.Code)
	}
	payload, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || payload.NodeSnapshot == nil || !reflect.DeepEqual(payload.Services["youtube"], selection) {
		t.Fatal("exact encrypted selection/source scope", err)
	}
	targetRoot := filepath.Join(t.TempDir(), "target")
	target := privateRestoreNodeApp(t, targetRoot)
	before := target.Store.Get()
	call := func(action string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple", "confirm": "IMPORT_PRIVATE_BACKUP"})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/"+action, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		target.Handler(http.NotFoundHandler()).ServeHTTP(response, request)
		return response
	}
	for _, action := range []string{"preview", "import"} {
		response := call(action)
		var result map[string]any
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result["draft_only"] != true || strings.Contains(response.Body.String(), "backup-node.example") {
			t.Fatalf("actual HTTP %s status=%d body=%s", action, response.Code, response.Body.String())
		}
		if action == "preview" && !reflect.DeepEqual(target.Store.Get(), before) {
			t.Fatal("preview changed original configuration")
		}
	}
	reloaded, err := config.LoadExisting(filepath.Join(targetRoot, "config.json"))
	if err != nil {
		t.Fatal("strict persisted config reload", err)
	}
	for _, cfg := range []config.Config{target.Store.Get(), reloaded.Get()} {
		if !reflect.DeepEqual(cfg.Services["youtube"], selection) || !reflect.DeepEqual(cfg.EngineOrder, before.EngineOrder) || !reflect.DeepEqual(cfg.AppliedServices, before.AppliedServices) || cfg.AppliedRevision != before.AppliedRevision {
			t.Fatal("restore lost selection/sources or promoted draft to live state")
		}
	}
	restored, err := target.Nodes.Snapshot(ctx, now)
	if err != nil || len(restored.Nodes) != 1 || restored.Nodes[0].ID != nodeID || restored.Nodes[0].Health.State != "not_checked" || restored.Nodes[0].State == "healthy" {
		t.Fatal("restored node acquired health evidence", err)
	}
	status := httptest.NewRecorder()
	target.Handler(http.NotFoundHandler()).ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/v1/mihomo/selection", nil))
	var state map[string]any
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &state) != nil || state["runtime_registered"] != false || state["live_apply_available"] != false || state["service_verified"] != false || state["live_applied"] != false {
		t.Fatal("restored draft manufactured original runtime/readiness", status.Code)
	}
}
