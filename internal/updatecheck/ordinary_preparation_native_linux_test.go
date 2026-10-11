//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A runner fixture, not genuine Main/HTTP future-update acceptance. Only the
// private temporary root is written, and no production /opt path is touched.
func ordinaryNativeRunnerImage(t *testing.T) (string, string, string) {
	t.Helper()
	if os.Geteuid() != 0 || checkRootOwnedPath("/root") != nil {
		t.Skip("isolated root-owned native runner fixture requires /root")
	}
	base, err := os.MkdirTemp("/root", "razvilka-ordinary-runner-")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(base) != "/root" || !strings.HasPrefix(filepath.Base(base), "razvilka-ordinary-runner-") {
		t.Fatal("unexpected private fixture root")
	}
	t.Cleanup(func() {
		if filepath.Dir(base) == "/root" && strings.HasPrefix(filepath.Base(base), "razvilka-ordinary-runner-") {
			if err := os.RemoveAll(base); err != nil {
				t.Error(err)
			}
		}
	})
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(shell)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "sh")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	return base, path, digestBytes(data)
}

func TestNativeOrdinaryImageCommandRevocationJoinsActualChild(t *testing.T) {
	base, path, sha := ordinaryNativeRunnerImage(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pidPath := filepath.Join(base, "child.pid")
	var child int
	starts, afters := 0, 0
	revoked := errors.New("original fixture owner revoked")
	started := time.Now()
	_, err := ordinaryImageCommand(ctx, path, sha, []string{"-c", `printf '%s\n' "$$" > "$1"; exec sleep 30`, "fixture", pidPath}, "ordinary-prepare-check", func(c context.Context, effect string, begin func() error) error {
		if c.Err() != nil || effect != "ordinary-prepare-check" {
			return errOrdinaryPreparation
		}
		starts++
		return begin()
	}, func() error { return nil }, func() error {
		data, err := os.ReadFile(pidPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		child, err = strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || child <= 1 {
			return errOrdinaryPreparation
		}
		return revoked
	}, func() error { afters++; return nil })
	if !errors.Is(err, revoked) || starts != 1 || afters != 0 || child <= 1 || time.Since(started) > 3*time.Second {
		t.Fatal("revocation did not join original Start/Wait", err, starts, afters, child)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(child, &status, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Fatal("original Wait was not consumed", err)
	}
	if err := syscall.Kill(child, 0); err != syscall.ESRCH {
		t.Fatal("joined child remains active", err)
	}
}

func TestNativeOrdinaryImageCommandRejectsReplacedHeldPathBeforeStart(t *testing.T) {
	base, path, sha := ordinaryNativeRunnerImage(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(base, "replacement")
	if err := os.WriteFile(replacement, data, 0700); err != nil {
		t.Fatal(err)
	}
	checks, starts := 0, 0
	_, err = ordinaryImageCommand(ctx, path, sha, []string{"-c", "exit 0"}, "ordinary-prepare-check", func(context.Context, string, func() error) error { starts++; return nil }, func() error {
		checks++
		if checks == 2 {
			return os.Rename(replacement, path)
		}
		return nil
	}, func() error { return nil }, func() error { return nil })
	if err == nil || starts != 0 || checks != 2 {
		t.Fatal("same-byte replaced inode admitted Start", err, starts, checks)
	}
}
