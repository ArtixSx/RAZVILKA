//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMihomoSameBootPIDFDChild(t *testing.T) {
	if os.Getenv("RAZVILKA_SAME_BOOT_PIDFD_CHILD") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

// Actual original Cmd/pidfd/sole Wait only. The validated/attempted fields here
// are explicitly documentary test inputs, NOT a CORE cleanup source or grant.
func sameBootActualPIDFD(t *testing.T) (*mihomoSameBootSidecar, *exec.Cmd, *bool) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestMihomoSameBootPIDFDChild$", "-test.count=1")
	command.Env = append(os.Environ(), "RAZVILKA_SAME_BOOT_PIDFD_CHILD=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(command.Process.Pid, 0) // BEFORE any Wait.
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	s := &mihomoSameBootSidecar{file: os.NewFile(uintptr(fd), "actual original test child pidfd"), validated: true, attempted: true, original: &mihomoSameBootStatic{}}
	s.self = s
	waited := new(bool)
	t.Cleanup(func() {
		if !*waited {
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			_ = command.Wait()
		}
		_ = s.close()
	})
	return s, command, waited
}

func TestMihomoSameBootPIDFDRetainsCanceledWaitAndObservesLateOriginalExit(t *testing.T) {
	s, command, waited := sameBootActualPIDFD(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := waitMihomoSameBootSidecarExit(ctx, s, s.original); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("actual live pidfd did not retain canceled wait", err)
	}
	if _, err := s.file.Stat(); err != nil {
		t.Fatal("canceled wait dropped original descriptor", err)
	}
	forged := &mihomoSameBootSidecar{self: s, original: s.original, file: s.file, validated: true, attempted: true}
	if waitMihomoSameBootSidecarExit(t.Context(), forged, s.original) == nil || forged.close() == nil {
		t.Fatal("copied custody observed/closed original")
	}
	if err := unix.PidfdSendSignal(int(s.file.Fd()), unix.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("original test child unexpectedly completed naturally")
	}
	*waited = true
	closing, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := waitMihomoSameBootSidecarExit(closing, s, s.original); err != nil {
		t.Fatal("same held pidfd cannot observe actual reaped child", err)
	}
	if s.terminal {
		t.Fatal("read-only wait fabricated full-source cleanup ACK")
	}
	if waitMihomoSameBootSidecarExit(closing, s, &mihomoSameBootStatic{}) == nil {
		t.Fatal("foreign source borrowed original pidfd")
	}
}

func TestMihomoSameBootPIDFDCloseFailureStaysVisible(t *testing.T) {
	s, command, waited := sameBootActualPIDFD(t)
	if err := unix.PidfdSendSignal(int(s.file.Fd()), unix.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	*waited = true
	if err := s.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitMihomoSameBootSidecarExit(t.Context(), s, s.original); !errors.Is(err, os.ErrClosed) {
		t.Fatal("externally closed original FD accepted", err)
	}
	for range 2 {
		if err := s.close(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("sticky actual Close exception lost", err)
		}
	}
}
