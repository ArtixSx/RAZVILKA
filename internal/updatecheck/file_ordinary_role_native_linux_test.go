//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This fixture tests the actual subreaper producer boundary, not production
// Main/HTTP or future-update acceptance. The synthetic quiescer owns no effect.
func observeNativeOrdinaryJoin(ctx context.Context, a *SelfUpdateFileAdapter, id string) error {
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	command, err := readFileCommand(root, id, "quiesce-old-runtime")
	if err != nil || command.State != "running" {
		return ErrOrdinaryInstallerControllerRole
	}
	join, err := ordinaryQuiesceJoinFor(ctx, a, command, os.Getpid())
	if err != nil || join == nil || join.reaped < 2 {
		return ErrOrdinaryInstallerControllerRole
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); err != syscall.ECHILD {
		return ErrOrdinaryInstallerControllerRole
	}
	return root.WriteAtomic("ordinary-join-observed", []byte("actual worker joined direct and adopted children\n"), 0600)
}

func TestNativeOrdinaryJoinIsProducedAfterActualAllChildWait(t *testing.T) {
	a, u, review, _ := nativeFileFixture(t, "ordinary-join")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Run(ctx, review.ID, "quiesce-old-runtime"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(u.Directory, review.ID, "ordinary-join-observed")); err != nil || string(data) != "actual worker joined direct and adopted children\n" {
		t.Fatal("actual worker did not publish the private join observation", err)
	}
	// A fresh caller with the same completed receipt has no original context.
	if !errors.Is(a.VerifyOrdinaryInstallerControllerRole(ctx, review.ID, os.Getpid()), ErrOrdinaryInstallerControllerRole) {
		t.Fatal("cold model observer borrowed completed-worker authority")
	}
}
