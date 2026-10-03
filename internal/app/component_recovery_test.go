package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestComponentJournalFencesWorkersAndPreservesStop(t *testing.T) {
	root := t.TempDir()
	a := &App{Components: &components.Manager{StateDir: root}}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	journalDir := filepath.Join(root, "update-journal")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"schema_version": 1, "transaction_id": strings.Repeat("a", 32), "component": "xray", "package": "xray", "phase": components.UpdateAwaitingLive, "before_version": "1.0", "after_version": "2.0", "updated_at": time.Now().UTC().Format(time.RFC3339Nano), "package_file": "xray_1.0_aarch64.ipk", "package_sha256": strings.Repeat("a", 64), "configs": []any{}})
	path := filepath.Join(journalDir, "current.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	release()
	if !a.PendingComponentRecovery() || !a.componentMaintenancePending() {
		t.Fatal("pending journal hidden")
	}
	for _, enter := range []func(context.Context) (func(), error){a.Operations.Enter, a.Operations.Exclusive} {
		if release, err := enter(context.Background()); release != nil || !errors.Is(err, errComponentRecovery) {
			t.Fatal("background bypassed pending record:", err)
		}
	}
	if release, err := a.Operations.Exclusive(componentStopContext(context.Background(), "resume")); release != nil || !errors.Is(err, errComponentRecovery) {
		t.Fatal("resume bypassed fence")
	}
	release, err = a.Operations.Exclusive(componentStopContext(context.Background(), "stop"))
	if err != nil {
		t.Fatal("explicit Stop blocked:", err)
	}
	release()
	if err := os.WriteFile(path, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if release, err := a.Operations.Exclusive(context.Background()); release != nil || !errors.Is(err, errComponentRecovery) {
		t.Fatal("corrupt record interpreted as clean")
	}
	a.Operations.FenceJournal()
	if release, err := a.Operations.Exclusive(componentStopContext(context.Background(), "stop")); release != nil || !errors.Is(err, operationgate.ErrJournalRecovery) {
		t.Fatal("component Stop escaped network recovery ownership")
	}
}
