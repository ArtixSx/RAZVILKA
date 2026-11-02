//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual protected history reader; the terminal rows are documentary models,
// not acknowledgments from a native probe or permission to revoke callbacks.
func TestMihomoTransitArchiveRequiresReader8AndCannotBecomeLatest(t *testing.T) {
	_, archive, after := mihomoTransitArchiveFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := filepath.Join(t.TempDir(), "history")
	write := func(name string, e Execution) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	name := filepath.Join("transactions", archive.PlanID, "execution.json")
	write(name, archive)
	write(filepath.Join("transactions", after.PlanID, "execution.json"), after)
	write("latest-execution.json", after)
	if version, seal, err := InspectRetainedExecutionReadVersion(ctx, root); err != nil || version != 8 || seal == "" {
		t.Fatal("retained archive did not require actual reader8", version, err)
	}
	write("latest-execution.json", archive)
	if _, _, err := InspectRetainedExecutionReadVersion(ctx, root); err == nil {
		t.Fatal("archive accepted as live latest")
	}
	write("latest-execution.json", after)
	marker := archive.MihomoTransitHistoryArchive.Clone()
	marker.OriginAfterSHA256 = strings.Repeat("f", 64)
	archive.MihomoTransitHistoryArchive = &marker
	write(name, archive)
	if _, _, err := InspectRetainedExecutionReadVersion(ctx, root); err == nil {
		t.Fatal("forged derived live image accepted by history scanner")
	}
}
