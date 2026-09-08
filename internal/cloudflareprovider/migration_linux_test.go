//go:build linux

package cloudflareprovider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestLegacyLinuxFIFOOpenCannotWaitForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.conf")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := openLegacyFile(root, filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	_ = file.Close()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("not a FIFO fixture")
	}
	sources, err := NewLegacySources([]LegacySpec{{ID: "fifo", Label: "FIFO", Kind: SourceUSQUE, Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Preview(context.Background(), "fifo"); !errors.Is(err, ErrLegacySource) {
		t.Fatal("FIFO accepted")
	}
}
