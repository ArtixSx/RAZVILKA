//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type usqueInitialNoCommand struct{ t *testing.T }

func (r usqueInitialNoCommand) Run(context.Context, string, ...string) ([]byte, error) {
	r.t.Fatal("unreviewed core reached sidecar execution")
	return nil, nil
}

func TestUSQUEInitialSourceRejectsUnpinnedInstalledCore(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	a, err := NewProxyTunnelAdapter("usque", configs, root)
	if err != nil {
		t.Fatal(err)
	}
	a.EngineBin = filepath.Join(root, "usque")
	if err := os.WriteFile(a.EngineBin, []byte("unreviewed fixture executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.Runner = usqueInitialNoCommand{t: t}
	m := New(root)
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if source, err := m.ReviewUSQUEInitialSource(context.Background(), configs); source != nil || !errors.Is(err, ErrUSQUEInitialSource) {
		t.Fatalf("unreviewed executable supplied startup authority: %v", err)
	}
}

func TestUSQUEInitialExecutableFencesPermissionDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("protected fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	asset, err := usqueInitialExecutableAt(path)
	if err != nil || !asset.current() {
		t.Fatalf("protected fixture was not reviewable: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if asset.current() {
		t.Fatal("permission-only change preserved the reviewed executable")
	}
}
