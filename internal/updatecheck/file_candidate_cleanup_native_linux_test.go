//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/unix"
)

// Actual H -> S -> C -> adopted R. All filesystem effects are in TempDir;
// no production argv/env path, network resource or canonical installation is
// overridden. These tests cover the private source, not production admission.
func TestCandidateCleanupNativeRuntimeFixture(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_CANDIDATE_ROLE") != "runtime" {
		return
	}
	control := os.NewFile(3, "original-runtime-lifetime")
	if control == nil {
		os.Exit(106)
	}
	defer control.Close()
	closed := make(chan struct{})
	go func() {
		_, _ = io.ReadFull(control, make([]byte, 1))
		close(closed)
	}()
	select {
	case <-closed:
		os.Exit(107) // Failure cleanup is never a successful runtime fixture.
	case <-time.After(45 * time.Second):
		os.Exit(106) // Backstop, including unexpected supervisor death.
	}
}

func TestCandidateCleanupNativeDirectFixture(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_CANDIDATE_ROLE") != "direct" {
		return
	}
	binary, err := os.Executable()
	if err != nil {
		os.Exit(91)
	}
	child := exec.Command(binary, "-test.run=^TestCandidateCleanupNativeRuntimeFixture$")
	child.Env = append(os.Environ(), "RAZVILKA_TEST_CANDIDATE_ROLE=runtime")
	control := os.NewFile(3, "original-runtime-lifetime")
	if control == nil {
		os.Exit(94)
	}
	child.ExtraFiles = []*os.File{control}
	if child.Start() != nil {
		os.Exit(92)
	}
	path := filepath.Join(os.Getenv("RAZVILKA_TEST_CANDIDATE_DIRECTORY"), "razvilka.pid")
	if os.WriteFile(path, []byte(strconv.Itoa(child.Process.Pid)+"\n"), 0600) != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		os.Exit(93)
	}
	control.Close()
	_ = child.Process.Release()
	os.Exit(0)
}

func TestCandidateCleanupNativeSupervisorFixture(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_CANDIDATE_ROLE") != "supervisor" {
		return
	}
	os.Exit(candidateCleanupNativeSupervisor())
}

// The lifetime pipe is retained before C starts and inherited by only the
// original R. Every error/EOF path closes it, waits the original C handle,
// then reaps adopted children. Cleanup never acquires authority by PID lookup.
func candidateCleanupNativeSupervisor() int {
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		return 91
	}
	binary, err := os.Executable()
	if err != nil {
		return 92
	}
	parent, err := fileProcessOf(os.Getppid())
	if err != nil {
		return 93
	}
	supervisor, err := fileProcessOf(os.Getpid())
	if err != nil {
		return 94
	}
	runtimeInput, runtimeLifetime, err := os.Pipe()
	if err != nil {
		return 109
	}
	defer runtimeInput.Close()
	child := exec.Command(binary, "-test.run=^TestCandidateCleanupNativeDirectFixture$")
	child.Env = append(os.Environ(), "RAZVILKA_TEST_CANDIDATE_ROLE=direct")
	child.ExtraFiles = []*os.File{runtimeInput}
	directWaited := false
	defer func() {
		runtimeLifetime.Close()
		if child.Process != nil && !directWaited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		deadline := time.Now().Add(5 * time.Second)
		for child.Process != nil {
			var status syscall.WaitStatus
			_, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
			if err == syscall.ECHILD {
				break
			}
			if err != nil && err != syscall.EINTR || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if child.Start() != nil {
		return 95
	}
	runtimeInput.Close()
	directPID := child.Process.Pid
	directWaited = true
	if child.Wait() != nil || !child.ProcessState.Success() {
		return 96
	}
	directory := os.Getenv("RAZVILKA_TEST_CANDIDATE_DIRECTORY")
	data, err := os.ReadFile(filepath.Join(directory, "razvilka.pid"))
	if err != nil {
		return 97
	}
	runtimePID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 98
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		_, ppid, err := fileBirth(runtimePID)
		if err == nil && ppid == os.Getpid() {
			break
		}
		if ctx.Err() != nil {
			return 99
		}
		time.Sleep(10 * time.Millisecond)
	}
	runtime, err := fileProcessOf(runtimePID)
	if err != nil {
		return 100
	}
	if os.Getenv("RAZVILKA_TEST_CANDIDATE_FAIL") == "before-ready" {
		return 108
	}
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ready := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: id, Command: "start-candidate-panel", State: "runtime-ready", Parent: parent, Supervisor: supervisor, Runtime: runtime, DirectPID: directPID, Reaped: 1}
	root, err := ownedfs.Open(directory)
	if err != nil {
		return 101
	}
	defer root.Close()
	if writeFileCommand(root, ready) != nil {
		return 102
	}
	barrier := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(os.Stdin, make([]byte, 1))
		barrier <- err
	}()
	select {
	case err := <-barrier:
		if err != nil {
			return 103
		}
	case <-ctx.Done():
		return 103
	}
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.ECHILD {
			break
		}
		if err != nil || ctx.Err() != nil {
			return 104
		}
		if pid > 0 {
			ready.Reaped++
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	ready.State, ready.WaitECHILD = "reaped", true
	if writeFileCommand(root, ready) != nil {
		return 105
	}
	return 0
}

func TestCandidateCleanupNativeOriginalSupervisorWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	directory := filepath.Join(t.TempDir(), id)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(binary, "-test.run=^TestCandidateCleanupNativeSupervisorFixture$")
	worker.Env = append(os.Environ(), "RAZVILKA_TEST_CANDIDATE_ROLE=supervisor", "RAZVILKA_TEST_CANDIDATE_DIRECTORY="+directory)
	worker.Stdin, worker.Stderr = input, os.Stderr
	if err := worker.Start(); err != nil {
		input.Close()
		release.Close()
		t.Fatal(err)
	}
	input.Close()
	var waitOnce sync.Once
	done := make(chan struct{})
	var waitErr error
	startWait := func() {
		waitOnce.Do(func() {
			go func() {
				waitErr = worker.Wait()
				close(done)
			}()
		})
	}
	t.Cleanup(func() {
		release.Close()
		startWait()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = worker.Process.Kill()
			<-done
		}
	})
	parent, err := fileProcessOf(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	supervisor, err := fileProcessOf(worker.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	a := NewSelfUpdateFileAdapter()
	if err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
		w, err := beginCandidateStartWait(held, a, id, worker, parent, supervisor)
		if err != nil {
			return err
		}
		var ready fileCommandReceipt
		for {
			ready, err = readFileCommand(root, id, "start-candidate-panel")
			if err == nil && ready.State == "runtime-ready" {
				break
			}
			if held.Err() != nil {
				return held.Err()
			}
			time.Sleep(10 * time.Millisecond)
		}
		pid, err := captureCandidatePID(directory, ready.Runtime.PID, syscall.O_NOFOLLOW)
		if err != nil {
			return err
		}
		if err := w.rememberReady(held, ready, pid); err != nil {
			pid.close()
			return err
		}
		// Open the kernel handle while the exact original runtime is live.
		fd, err := unix.PidfdOpen(ready.Runtime.PID, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		actual, err := fileProcessOf(ready.Runtime.PID)
		if err != nil || actual != ready.Runtime {
			return ErrFileProtocol
		}
		if err := unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0); err != nil {
			return err
		}
		if _, err := release.Write([]byte{1}); err != nil {
			return err
		}
		release.Close()
		startWait()
		<-done
		w.observeWait(waitErr) // The actual sole H Wait, not a JSON claim.
		final, err := readFileCommand(root, id, "start-candidate-panel")
		if err != nil || final.State != "reaped" || final.Reaped != 2 || !final.WaitECHILD {
			return errors.Join(ErrFileProtocol, err)
		}
		// The retained start state reproduces the old live-only guard refusal.
		observer := NewSelfUpdateFileAdapter()
		observer.directory = filepath.Dir(directory)
		if err := observer.ownedPanelBeforeStop(id, fileReview{}, "stop-candidate-panel"); !errors.Is(err, ErrFileProtocol) {
			t.Fatal("live guard accepted reaped start", err)
		}
		effects := 0
		if err := executeCandidateCleanup(held, w, final, func() error { return candidateProcessesAbsent(held, ready) }, func(begin func() error) error { return begin() }, func(p *candidatePIDImage) error { effects++; return removeCandidatePID(p) }); err != nil {
			return err
		}
		if effects != 1 {
			t.Fatal("known absence did not remove exact stale PID", effects)
		}
		if _, err := os.Lstat(filepath.Join(directory, "razvilka.pid")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("PID remained", err)
		}
		live, wait := ordinaryInstallerActualChild(t, 0)
		for _, member := range []string{"supervisor", "direct", "runtime"} {
			changed := ready
			switch member {
			case "supervisor":
				changed.Supervisor.PID, changed.Supervisor.Start = live.Process.Pid, "1"
			case "direct":
				changed.DirectPID = live.Process.Pid
			case "runtime":
				changed.Runtime.PID, changed.Runtime.Start = live.Process.Pid, "1"
			}
			if err := candidateProcessesAbsent(held, changed); err == nil {
				t.Fatal("live/reused PID granted absence", member)
			}
		}
		if err := wait(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateCleanupNativeFailureReapsRuntime(t *testing.T) {
	for _, mode := range []string{"before-ready", "barrier-eof"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			input, release, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			worker := exec.Command(binary, "-test.run=^TestCandidateCleanupNativeSupervisorFixture$")
			worker.Env = append(os.Environ(), "RAZVILKA_TEST_CANDIDATE_ROLE=supervisor", "RAZVILKA_TEST_CANDIDATE_DIRECTORY="+directory, "RAZVILKA_TEST_CANDIDATE_FAIL="+mode)
			worker.Stdin, worker.Stderr = input, os.Stderr
			if err := worker.Start(); err != nil {
				input.Close()
				release.Close()
				t.Fatal(err)
			}
			input.Close()
			done := make(chan error, 1)
			go func() { done <- worker.Wait() }() // The sole original H Wait.
			waited := false
			t.Cleanup(func() {
				release.Close()
				if !waited {
					_ = worker.Process.Kill()
					<-done
				}
			})
			release.Close() // EOF must retire the original R and reap it.
			select {
			case err := <-done:
				waited = true
				var exit *exec.ExitError
				want := 103
				if mode == "before-ready" {
					want = 108
				}
				if !errors.As(err, &exit) || exit.ExitCode() != want {
					t.Fatal("fixture did not reach intended error cleanup", err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("original supervisor did not finish failure cleanup")
			}
			data, err := os.ReadFile(filepath.Join(directory, "razvilka.pid"))
			if err != nil {
				t.Fatal(err)
			}
			runtimePID, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil || runtimePID <= 1 {
				t.Fatal("runtime fixture did not publish its original PID", err)
			}
			if _, err := os.Stat("/proc/" + strconv.Itoa(runtimePID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failure cleanup left original runtime or zombie", err)
			}
		})
	}
}

func TestCandidateCleanupNativeColdObserveMissingStopLedger(t *testing.T) {
	a, _, review, _ := nativeFileFixture(t, "normal")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := a.Observe(ctx, review.ID, "stop-candidate-panel"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cold missing ledger was not the refusal boundary", err)
	}
}
