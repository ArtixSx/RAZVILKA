//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSelfUpdatePreflightCancellationJoinsDescendantPipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & wait")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	started := time.Now()
	if runBoundedCommand(command) == nil {
		t.Fatal("cancelled preflight reported success")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("descendant held preparation after cancellation")
	}
}

func TestSelfUpdateInstallerDestinationsRejectSymlinkBeforeWrites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership guard requires uid 0")
	}
	base := t.TempDir()
	inspect := func(path string) error { return checkOwnedAncestors(path, base) }
	if err := checkInstallerWritePaths(base, inspect); err != nil {
		t.Fatalf("private empty install root refused: %v", err)
	}
	outside := filepath.Join(base, "untouched")
	if err := os.WriteFile(outside, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "var/lib/razvilka/current-backup")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := checkInstallerWritePaths(base, inspect); err == nil {
		t.Fatal("installer accepted current-backup symlink")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "preserved" {
		t.Fatal("refusal touched foreign destination")
	}
}

func TestSelfUpdateInstallerExitCannotWaitForeverForInheritedPipe(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30 & exit 0")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	started := time.Now()
	err := runTransactionalInstaller(command, 5*time.Second)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("unjoined descendant falsely successful: %v", err)
	}
	if time.Since(started) > 4*time.Second {
		t.Fatal("installer inherited pipe exceeded bounded cleanup")
	}
}
