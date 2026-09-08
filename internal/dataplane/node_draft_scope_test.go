package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestExactNodeSnapshotRejectsLegacyDraftAuthorityBeforeAnyWrite(t *testing.T) {
	configRoot := t.TempDir()
	configs := engineconfig.New(filepath.Join(configRoot, "stage"), filepath.Join(configRoot, "backups"))
	const draft = "{\n  \"outbounds\": []\n}\n"
	if _, err := configs.Stage("sing-box", "main", draft); err != nil {
		t.Fatal(err)
	}
	a, err := NewProxyTunnelAdapter("sing-box", configs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	transaction := filepath.Join(t.TempDir(), "must-not-exist")
	plan := Plan{NetworkProfileID: "wan-0123456789ab", EngineDrafts: []string{"sing-box/main"}, Routes: []Route{{ServiceID: "telegram", Selected: "sing-box:group-test", Resolved: "sing-box:node-test", Sources: []string{"192.168.1.40/32"}}}}
	if err := a.Snapshot(context.Background(), plan, transaction); err == nil {
		t.Fatal("snapshot accepted unrelated editor draft authority")
	}
	if _, err := os.Stat(transaction); !os.IsNotExist(err) {
		t.Fatal("refused snapshot wrote transaction files")
	}
	view, err := configs.ReadExpert("sing-box", "main")
	if err != nil || view.Source != "staged" || view.Content != draft {
		t.Fatal("refusal changed user draft")
	}
}
