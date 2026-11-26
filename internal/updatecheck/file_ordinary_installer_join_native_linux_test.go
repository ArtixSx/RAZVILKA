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
	"syscall"
	"testing"
	"time"
)

// Actual local H -> S -> C, including S's direct-child Wait and ECHILD.
// This fixture owns no runtime/network resource and is not production role
// admission; the genuine release pair remains Root's separate acceptance.
func TestOrdinaryInstallerJoinNativeSupervisor(t *testing.T) {
	resultPath := os.Getenv("RAZVILKA_TEST_ORDINARY_JOIN_RESULT")
	if resultPath == "" {
		return
	}
	binary, err := os.Executable()
	if err != nil {
		os.Exit(99)
	}
	child := exec.Command(binary, "-test.run=^TestOrdinaryInstallerJoinActualChild$")
	child.Env = append(os.Environ(), "RAZVILKA_TEST_ORDINARY_JOIN_CHILD=0")
	child.Stdin = strings.NewReader("1")
	if err := child.Run(); err != nil {
		os.Exit(98)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); err != syscall.ECHILD {
		os.Exit(97)
	}
	if err := os.WriteFile(resultPath, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
		os.Exit(96)
	}
	if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		os.Exit(95)
	}
	os.Exit(0)
}

func TestOrdinaryInstallerJoinNativeActualChainAndPIDReuseRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a := NewSelfUpdateFileAdapter()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		parent, err := fileProcessOf(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		input, release, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer release.Close()
		resultPath := filepath.Join(t.TempDir(), "actual-child-pid")
		worker := exec.Command(binary, "-test.run=^TestOrdinaryInstallerJoinNativeSupervisor$")
		worker.Env = append(os.Environ(), "RAZVILKA_TEST_ORDINARY_JOIN_RESULT="+resultPath)
		worker.Stdin = input
		if err := worker.Start(); err != nil {
			input.Close()
			t.Fatal(err)
		}
		input.Close()
		defer func() {
			if worker.ProcessState == nil {
				_ = worker.Process.Kill()
				_ = worker.Wait()
			}
		}()
		supervisor, err := fileProcessOf(worker.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		birth, ppid, err := fileBirth(supervisor.PID)
		if err != nil || birth != supervisor.Start || ppid != parent.PID {
			t.Fatal("actual S is not the original exec child", birth, ppid, err)
		}
		w, err := beginOrdinaryInstallerWait(held, a, id, worker, parent, supervisor)
		if err != nil {
			t.Fatal(err)
		}
		var result []byte
		for {
			result, err = os.ReadFile(resultPath)
			if err == nil && len(result) > 0 {
				break
			}
			if held.Err() != nil {
				t.Fatal("actual S/C join did not complete", held.Err(), err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		childPID, err := strconv.Atoi(string(result))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := release.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		release.Close()
		w.observeWait(worker.Wait())
		command := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: id, Command: "quiesce-old-runtime", State: "reaped", Parent: parent, Supervisor: supervisor, DirectPID: childPID, Reaped: 1, WaitECHILD: true}
		if err := w.complete(held, command); err != nil {
			t.Fatal(err)
		}
		if actual, err := w.owner.joined(held, a, id, os.Getpid()); err != nil || actual != command {
			t.Fatal("actual sole Wait did not establish original H provenance", actual, err)
		}
		if err := ordinaryJoinedProcessesAbsent(held, command); err != nil {
			t.Fatal("actual joined S/C are still present", err)
		}
		live, wait := ordinaryInstallerActualChild(t, 0)
		for _, mode := range []string{"reused-supervisor", "live-child"} {
			changed := command
			if mode == "reused-supervisor" {
				changed.Supervisor.PID = live.Process.Pid
				changed.Supervisor.Start = "1" // stale birth cannot waive the live PID
			} else {
				changed.DirectPID = live.Process.Pid
			}
			if err := ordinaryJoinedProcessesAbsent(held, changed); !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
				t.Fatal("live/reused PID granted absence", mode, err)
			}
		}
		if err := wait(); err != nil {
			t.Fatal(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
