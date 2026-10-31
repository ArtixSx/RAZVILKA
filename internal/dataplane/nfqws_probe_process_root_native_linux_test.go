//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"golang.org/x/sys/unix"
)

func TestNFQWSProbeProcessMarkerFIFORefusesWithoutBlocking(t *testing.T) {
	root := privateScopedXrayFixtureDir(t)
	target, err := restorejournal.OpenFileTarget(filepath.Join(root, nfqws2LeaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	key := sha256.Sum256([]byte(nfqws2LeaseFile))
	marker := filepath.Join(root, ".state-"+hex.EncodeToString(key[:])+".lock")
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(marker, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		owner, err := newNFQWSProbeProcessRoot(ctx, root, target)
		if owner != nil {
			_ = owner.close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO became retained writer identity")
		}
	case <-ctx.Done():
		t.Fatal("FIFO marker blocked original producer")
	}
}
