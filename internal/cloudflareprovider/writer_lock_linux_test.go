//go:build linux

package cloudflareprovider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriterLinuxFIFOOpenCannotBlock(t *testing.T) {
	s, path := privateStore(t)
	if err := syscall.Mkfifo(filepath.Join(path, writerLockFile), 0o600); err != nil {
		t.Fatal(err)
	}
	// Also exercise the final open path used if a regular file becomes a FIFO
	// between the initial stat and open: O_NONBLOCK must avoid waiting.
	file, err := openWriterFile(s.root, false)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	_ = file.Close()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("invalid FIFO fixture")
	}
	if release, err := s.lockWrite(context.Background()); !errors.Is(err, ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("FIFO lock accepted: %v", err)
	}
}
