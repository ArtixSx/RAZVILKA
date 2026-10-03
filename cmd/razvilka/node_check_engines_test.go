package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestConfiguredNodeCheckersShareOneQuotaAndCreateNoState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	dispatch, views, err := configuredNodeCheckers(root)
	if err != nil {
		t.Fatal(err)
	}
	if dispatch.Capacity() != 2 || len(views) != 2 {
		t.Fatal("quota doubled", dispatch.Capacity(), len(views))
	}
	for _, engine := range []string{"sing-box", "xray"} {
		fixed, ok := views[engine].(*dataplane.DispatchedNodeChecker)
		if !ok || fixed.EngineID() != engine || fixed.Capacity() != dispatch.Capacity() {
			t.Fatal("view lost exact engine/quota", engine)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("dispatcher construction wrote state", err)
	}
}

func TestNodeHistoryReadCapabilityMatchesNativeReader(t *testing.T) {
	output, err := selfUpdateMainSubprocess(t, "-node-history-read-version")
	if err != nil || strings.TrimSpace(string(output)) != "2" {
		t.Fatal("reader capability missing", string(output), err)
	}
}
