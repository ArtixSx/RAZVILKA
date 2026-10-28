//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func TestExactNodeRemovalIPv6AbsenceNeedsNativeFamilyRefusal(t *testing.T) {
	for _, failure := range []error{nil, syscall.EAFNOSUPPORT, syscall.EPERM, syscall.EMFILE, syscall.ENOPROTOOPT, syscall.EINVAL} {
		closed := 0
		got := exactNodeIPv6UnavailableWithSocket(func() (int, error) { return 123, failure }, func(fd int) error {
			if fd != 123 {
				t.Fatal("closed an unrelated descriptor")
			}
			closed++
			return nil
		})
		if got != (failure == syscall.EAFNOSUPPORT) || (closed == 1) != (failure == nil) {
			t.Fatal("unknown error or supported IPv6 granted absence", failure, got, closed)
		}
	}
}

func TestExactNodeRemovalPreflightRefusesFIFOConfigBeforeCapture(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node-check", "slot-1")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	pid := os.Getpid()
	if err := os.WriteFile(filepath.Join(dir, "engine.pid"), []byte(strconv.Itoa(pid)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	receipt, err := json.Marshal(routeidentity.Receipt{Version: 1, PID: pid, Executable: "/opt/bin/sing-box", ConfigHash: routeidentity.Hash([]byte("{}"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "engine.pid.identity.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "engine.json")
	if err := syscall.Mkfifo(config, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { done <- exactNodeRemovalOwnedListener(context.Background(), root, 19182, []string{"991"}) }()
	select {
	case admitted := <-done:
		if admitted {
			t.Fatal("FIFO config granted ownership")
		}
	case <-time.After(time.Second):
		// Unblock a regressed ReadFile before failing; never leave the test's
		// FIFO reader behind. This writes only to this private fixture FIFO.
		fd, err := syscall.Open(config, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
		}
		t.Fatal("ownership capture opened the FIFO before regular-file admission")
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	oversized, err := os.Create(config)
	if err != nil {
		t.Fatal(err)
	}
	truncateErr := oversized.Truncate((8 << 20) + 1)
	closeErr := oversized.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatal("oversized private config fixture", truncateErr, closeErr)
	}
	if exactNodeRemovalOwnedListener(context.Background(), root, 19182, []string{"991"}) {
		t.Fatal("config larger than the launcher's 8 MiB limit granted ownership")
	}
	current, err := os.ReadFile(filepath.Join(dir, "engine.pid.identity.json"))
	if err != nil || string(current) != string(receipt) {
		t.Fatal("config refusal changed original receipt", err)
	}
}
