package app

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func attachStrategyBackupFixture(t *testing.T, a *App, root string, seed bool) string {
	t.Helper()
	path := filepath.Join(root, "strategy-lab.json")
	if seed {
		state := strategylab.State{SchemaVersion: 4, Candidates: map[string]strategylab.Candidate{"candidate": {ID: "candidate", Incarnation: strings.Repeat("a", 32), PoolID: "tcp-tls", Name: "private-strategy-marker", Arguments: "--filter-tcp=443", Origin: "manual", Validation: strategylab.Validation{OK: true, Native: true, Generation: strings.Repeat("b", 32), Code: "PASS"}}}, Selections: map[string]strategylab.Selection{}}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	a.StrategyLab, err = strategylab.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.PrivateRestore.Close(); err != nil {
		t.Fatal(err)
	}
	c, _, err := privaterestore.Open(context.Background(), privaterestore.Layout{Config: filepath.Join(root, "config.json"), CustomServices: filepath.Join(root, "custom.json"), Devices: filepath.Join(root, "devices.json"), StageRoot: a.EngineConfigs.StageRoot, ProviderRoot: filepath.Join(root, "provider"), StrategyLabPath: path, JournalRoot: filepath.Join(root, "journal-strategy")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err = c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	a.PrivateRestore = c
	return path
}
func TestPrivateStrategyBackupEncryptedRoundTripRetiresAuthority(t *testing.T) {
	source, sourceRoot := privateRestoreTestApp(t)
	attachStrategyBackupFixture(t, source, sourceRoot, true)
	exported := requestPrivateBackupExport(source)
	var envelope privatebackup.Envelope
	if exported.Code != 200 || json.Unmarshal(exported.Body.Bytes(), &envelope) != nil || strings.Contains(exported.Body.String(), "private-strategy-marker") {
		t.Fatalf("unsafe export HTTP %d", exported.Code)
	}
	payload, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || payload.StrategyLabSnapshot == nil {
		t.Fatal("StrategyLab omitted", err)
	}
	target, targetRoot := privateRestoreTestApp(t)
	path := attachStrategyBackupFixture(t, target, targetRoot, false)
	before := target.Store.Get()
	call := func(action string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple", "confirm": "IMPORT_PRIVATE_BACKUP"})
		w := httptest.NewRecorder()
		target.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/"+action, bytes.NewReader(body)))
		return w
	}
	target.StrategyLab = nil
	refused := call("preview")
	if refused.Code == 200 {
		t.Fatal("preview accepted unavailable StrategyLab manager")
	}
	target.StrategyLab, err = strategylab.New(path)
	if err != nil {
		t.Fatal(err)
	}
	preview := call("preview")
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), `"strategy_lab":true`) || !strings.Contains(preview.Body.String(), `"draft_only":true`) {
		t.Fatalf("preview HTTP %d %s", preview.Code, preview.Body.String())
	}
	imported := call("import")
	if imported.Code != 200 || !strings.Contains(imported.Body.String(), `"draft_only":true`) {
		t.Fatalf("import HTTP %d %s", imported.Code, imported.Body.String())
	}
	if !reflect.DeepEqual(before.AppliedServices, target.Store.Get().AppliedServices) {
		t.Fatal("restore changed applied routes")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state strategylab.State
	if json.Unmarshal(data, &state) != nil {
		t.Fatal("invalid restored bytes")
	}
	candidate := state.Candidates["candidate"]
	if candidate.Name != "private-strategy-marker" || candidate.Incarnation != strings.Repeat("a", 32) || candidate.Validation.Generation != strings.Repeat("b", 32) || candidate.Validation.OK || candidate.Validation.Native {
		t.Fatal("restore lost candidate identity or revived validation authority")
	}
}
