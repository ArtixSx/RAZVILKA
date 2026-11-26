//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"golang.org/x/sys/unix"
)

const (
	backendCLINativeOptIn   = "RAZVILKA_BACKEND_CLI_NATIVE"
	backendCLINativeRole    = "RAZVILKA_BACKEND_CLI_ROLE"
	backendCLINativeCase    = "RAZVILKA_BACKEND_CLI_CASE"
	backendCLINativeState   = "RAZVILKA_BACKEND_CLI_STATE"
	backendCLINativeProgram = "RAZVILKA_BACKEND_CLI_PROGRAM"
	backendCLINativePIDBase = "RAZVILKA_BACKEND_CLI_BASE_PIDNS"
)

// The hardlinked private CLI must accept exactly the real runner's -t/-S
// argv. Dispatch before testing parses flags, only in this opt-in fixture.
// This init is absent from production binaries and ordinary tests.
func init() {
	role := os.Getenv(backendCLINativeRole)
	if role == "cli" || role == "leaf" {
		os.Exit(backendCLINativeEntry(role))
	}
}

func backendCLINativeIsolated() error {
	current, err := os.Readlink("/proc/self/ns/pid")
	base := os.Getenv(backendCLINativePIDBase)
	if err != nil || os.Getenv(backendCLINativeOptIn) != "1" || os.Geteuid() != 0 || base == "" || current == base {
		return errors.Join(errBackendInventory, err)
	}
	return nil
}

func backendCLINativeWrite(path string, value any) error {
	if err := nfqws2ManagedProtected(path, true); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(data)
	closeErr := file.Close()
	if n != len(data) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	return errors.Join(writeErr, closeErr)
}

func backendCLINativeRecord(dir, role string) error {
	identity, err := components.ReadNFQWSRuntimeProcessIdentity(os.Getpid())
	if err != nil {
		return err
	}
	return backendCLINativeWrite(filepath.Join(dir, role+".json"), identity)
}

func backendCLINativeReady(dir, role string) error {
	return backendCLINativeWrite(filepath.Join(dir, role+"-ready.json"), true)
}

func backendCLINativeAwaitFile(path string, deadline time.Time) error {
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	return context.DeadlineExceeded
}

func backendCLINativeEntry(role string) int {
	program, err := os.Executable()
	dir, mode := os.Getenv(backendCLINativeState), os.Getenv(backendCLINativeCase)
	if err != nil || backendCLINativeIsolated() != nil || program != os.Getenv(backendCLINativeProgram) || nfqws2ManagedProtected(program, false) != nil || !nfqws2ManagedPath(dir) || len(os.Args) != 4 || os.Args[1] != "-t" || os.Args[2] != "mangle" || os.Args[3] != "-S" {
		return 91
	}
	if err := backendCLINativeRecord(dir, role); err != nil {
		return 92
	}
	if role == "leaf" {
		if backendCLINativeReady(dir, role) != nil {
			return 92
		}
		// Keep inherited stdout/stderr open without writing after pipe closure.
		// This detached private leaf is killed/reaped by the separate worker.
		time.Sleep(30 * time.Second)
		return 93
	}
	if strings.HasPrefix(mode, "inherited-") {
		leaf := exec.Command(program, "-t", "mangle", "-S")
		leaf.Env = backendCLINativeEnv(os.Environ(), backendCLINativeRole, "leaf")
		leaf.Stdout, leaf.Stderr = os.Stdout, os.Stderr
		leaf.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if leaf.Start() != nil {
			return 94
		}
		// The child writes its exact birth before the parent is allowed to exit.
		if backendCLINativeAwaitFile(filepath.Join(dir, "leaf-ready.json"), time.Now().Add(time.Second)) != nil {
			return 95
		}
		_ = leaf.Process.Release() // Only the isolated worker reaps this leaf.
	}
	prefix := []byte("-P OUTPUT ACCEPT\n")
	switch mode {
	case "valid":
		if _, err := os.Stdout.Write(prefix); err != nil {
			return 96
		}
		if _, err := os.Stderr.Write([]byte("-N NOTICE\n")); err != nil {
			return 96
		}
		return 0
	case "stdout-overflow", "stderr-overflow":
		output := os.Stdout
		if mode == "stderr-overflow" {
			output = os.Stderr
		}
		_, _ = output.Write(bytes.Repeat([]byte{'x'}, 128<<10))
	case "combined-overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'o'}, 16))
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'e'}, 16))
		_, _ = os.Stderr.Write([]byte{'x'})
	case "deadline", "cancel", "inherited-exit", "inherited-cancel", "inherited-deadline":
		if _, err := os.Stdout.Write(prefix); err != nil {
			return 96
		}
		if backendCLINativeReady(dir, "cli") != nil {
			return 92
		}
		if mode == "inherited-exit" {
			return 0
		}
	default:
		return 97
	}
	for {
		time.Sleep(time.Second)
	}
}

func backendCLINativeEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, key+"=") {
			out = append(out, entry)
		}
	}
	return append(out, key+"="+value)
}

func backendCLINativeRead(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 16384 {
		return errors.Join(errBackendInventory, readErr, closeErr)
	}
	return json.Unmarshal(data, value)
}

// PIDFD plus two-sided boot/start/group checks confines cleanup to the exact
// private fixture birth, including a zombie. No group-wide/broad PID kill.
func backendCLINativeCleanupIdentity(identity components.NFQWSRuntimeProcessIdentity) error {
	if identity.PID <= 1 {
		return errBackendInventory
	}
	fd, err := unix.PidfdOpen(identity.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	want := components.NFQWSSupervisionIdentity{BootID: identity.BootID, Start: identity.Start, PID: identity.PID, Group: identity.Group}
	first, err := components.ReadNFQWSSupervisionProcessIdentity(identity.PID)
	if err != nil || first != want {
		return errors.Join(errBackendInventory, err)
	}
	last, err := components.ReadNFQWSSupervisionProcessIdentity(identity.PID)
	if err != nil || last != want {
		return errors.Join(errBackendInventory, err)
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var status unix.WaitStatus
		pid, err := unix.Wait4(identity.PID, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", identity.PID)); !errors.Is(statErr, os.ErrNotExist) {
				return errors.Join(errBackendInventory, statErr)
			}
			return nil // Already waited by command.Run; no process remains.
		}
		if err != nil {
			return err
		}
		if pid == identity.PID {
			if !status.Exited() && !status.Signaled() {
				return errBackendInventory
			}
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return context.DeadlineExceeded
}

func backendCLINativeCleanup(dir string) error {
	var result error
	for _, role := range []string{"cli", "leaf"} {
		var identity components.NFQWSRuntimeProcessIdentity
		if err := backendCLINativeRead(filepath.Join(dir, role+".json"), &identity); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			result = errors.Join(result, err)
			continue
		}
		result = errors.Join(result, backendCLINativeCleanupIdentity(identity))
	}
	return result
}

func backendCLINativeNoChildren() error {
	var status unix.WaitStatus
	pid, err := backendCLINativeWait(-1, &status)
	if pid == -1 && errors.Is(err, unix.ECHILD) {
		return nil
	}
	return fmt.Errorf("private fixture still has a child: pid=%d status=%d error=%v", pid, status, err)
}

func backendCLINativeWait(pid int, status *unix.WaitStatus) (int, error) {
	for range 8 {
		waited, err := unix.Wait4(pid, status, unix.WNOHANG, nil)
		if !errors.Is(err, unix.EINTR) {
			return waited, err
		}
	}
	return -1, unix.EINTR
}

type backendCLINativeProof struct {
	Case                                                      string
	ElapsedMS                                                 int64
	ReturnedBytes                                             int
	DirectWaitECHILD, LeafAliveAfterRun, FixtureCleanupECHILD bool
}

func backendCLINativeWorker(mode, dir, program string) (proof backendCLINativeProof, result error) {
	proof.Case = mode
	switch mode {
	case "valid", "stdout-overflow", "stderr-overflow", "combined-overflow", "deadline", "cancel", "inherited-exit", "inherited-cancel", "inherited-deadline":
	default:
		return proof, errBackendInventory
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return proof, err
	}
	// This process is a dedicated private test worker, never the daemon/test
	// controller. command.Run owns CLI Wait; this worker owns only adopted leaf.
	defer func() {
		cleanupErr := backendCLINativeCleanup(dir)
		childrenErr := backendCLINativeNoChildren()
		proof.FixtureCleanupECHILD = cleanupErr == nil && childrenErr == nil
		result = errors.Join(result, cleanupErr, childrenErr)
	}()
	budget := 2 * time.Second
	if mode == "deadline" {
		budget = 350 * time.Millisecond
	}
	if mode == "inherited-deadline" {
		budget = 700 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var stopped chan error
	if mode == "cancel" || mode == "inherited-cancel" {
		stopped = make(chan error, 1)
		go func() {
			err := backendCLINativeAwaitFile(filepath.Join(dir, "cli-ready.json"), time.Now().Add(1500*time.Millisecond))
			cancel()
			stopped <- err
		}()
	}
	limit := 64
	if strings.Contains(mode, "overflow") {
		limit = 32
	}
	start := time.Now()
	// Dedicated role/env applies only to this test executable. The production
	// method fixes its environment; both use the same bounded execution body.
	output, err := backendInventoryRunBounded(ctx, program, limit, os.Environ(), "-t", "mangle", "-S")
	elapsed := time.Since(start)
	proof.ElapsedMS, proof.ReturnedBytes = elapsed.Milliseconds(), len(output)
	if stopped != nil {
		if readyErr := <-stopped; readyErr != nil {
			return proof, readyErr
		}
	}
	if elapsed > budget+250*time.Millisecond {
		return proof, fmt.Errorf("runner escaped runtime bound: %v vs %v", elapsed, budget)
	}
	var direct components.NFQWSRuntimeProcessIdentity
	if readErr := backendCLINativeRead(filepath.Join(dir, "cli.json"), &direct); readErr != nil {
		return proof, readErr
	}
	if direct.Executable != program || direct.ArgumentsSHA256 != components.NFQWSRuntimeArgumentsSHA256(program, []string{"-t", "mangle", "-S"}) || direct.ParentPID != os.Getpid() {
		return proof, errBackendInventory
	}
	var status unix.WaitStatus
	pid, waitErr := backendCLINativeWait(direct.PID, &status)
	proof.DirectWaitECHILD = pid == -1 && errors.Is(waitErr, unix.ECHILD)
	if !proof.DirectWaitECHILD {
		return proof, fmt.Errorf("command.Run did not own and finish direct Wait: pid=%d error=%v", pid, waitErr)
	}
	if mode == "valid" {
		if err != nil || string(output) != "-P OUTPUT ACCEPT\n-N NOTICE\n" {
			return proof, fmt.Errorf("valid combined output lost: %q %v", output, err)
		}
	} else if err == nil || output != nil {
		return proof, fmt.Errorf("failed CLI returned partial/success output: %d %v", len(output), err)
	}
	if strings.Contains(mode, "overflow") && (ctx.Err() != nil || !errors.Is(err, context.Canceled)) {
		return proof, fmt.Errorf("overflow did not trigger internal cancel: %v original=%v", err, ctx.Err())
	}
	if strings.Contains(mode, "deadline") && !errors.Is(err, context.DeadlineExceeded) {
		return proof, fmt.Errorf("deadline lost: %v", err)
	}
	if strings.Contains(mode, "cancel") && !errors.Is(err, context.Canceled) {
		return proof, fmt.Errorf("cancel lost: %v", err)
	}
	if mode == "inherited-exit" && (!errors.Is(err, exec.ErrWaitDelay) || elapsed < 80*time.Millisecond || ctx.Err() != nil) {
		return proof, fmt.Errorf("live inherited pipe did not hit WaitDelay: %v after %v", err, elapsed)
	}
	if strings.HasPrefix(mode, "inherited-") {
		var leaf components.NFQWSRuntimeProcessIdentity
		if readErr := backendCLINativeRead(filepath.Join(dir, "leaf.json"), &leaf); readErr != nil {
			return proof, readErr
		}
		actual, readErr := components.ReadNFQWSRuntimeProcessIdentity(leaf.PID)
		leaf.ParentPID = os.Getpid() // Exact birth survives reparent to this subreaper.
		proof.LeafAliveAfterRun = readErr == nil && actual == leaf && leaf.Group == leaf.PID && leaf.Executable == program && leaf.ArgumentsSHA256 == direct.ArgumentsSHA256
		if !proof.LeafAliveAfterRun {
			return proof, fmt.Errorf("fixture did not demonstrate live detached leaf after direct Wait: %v", readErr)
		}
	}
	return proof, nil
}

func TestBackendInventoryCLILimitsNativeWorker(t *testing.T) {
	if os.Getenv(backendCLINativeRole) != "worker" {
		t.Skip("private native worker only")
	}
	if err := backendCLINativeIsolated(); err != nil {
		t.Fatal("worker requires ROOT private PID namespace", err)
	}
	dir, program, mode := os.Getenv(backendCLINativeState), os.Getenv(backendCLINativeProgram), os.Getenv(backendCLINativeCase)
	if nfqws2ManagedProtected(program, false) != nil || !nfqws2ManagedPath(dir) {
		t.Fatal("unprotected native fixture")
	}
	t.Setenv(backendCLINativeRole, "cli")
	proof, err := backendCLINativeWorker(mode, dir, program)
	if err != nil {
		t.Fatal("actual bounded CLI fixture", proof, err)
	}
	if err := backendCLINativeWrite(filepath.Join(dir, "proof.json"), proof); err != nil {
		t.Fatal(err)
	}
}

func TestBackendInventoryCLILimitsNative(t *testing.T) {
	if os.Getenv(backendCLINativeOptIn) != "1" {
		t.Skip("ROOT-only private native CLI limit harness")
	}
	if os.Getenv(backendCLINativeRole) != "" || os.Getpid() != 1 || backendCLINativeIsolated() != nil {
		t.Fatal("run the dedicated PID namespace harness; no host/subreaper mutation")
	}
	program, err := os.Executable()
	cli := os.Getenv(backendCLINativeProgram)
	if err != nil || nfqws2ManagedProtected(program, false) != nil || nfqws2ManagedProtected(cli, false) != nil {
		t.Fatal("unprotected private executables", err)
	}
	original, err := os.Stat(program)
	alias, aliasErr := os.Stat(cli)
	if err != nil || aliasErr != nil || !os.SameFile(original, alias) {
		t.Fatal("CLI must be the private hardlink of this exact test binary", err, aliasErr)
	}
	for _, mode := range []string{"valid", "stdout-overflow", "stderr-overflow", "combined-overflow", "deadline", "cancel", "inherited-exit", "inherited-cancel", "inherited-deadline"} {
		if !t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			output := &backendInventoryOutput{limit: 16 << 10, onOverflow: cancel}
			worker := exec.CommandContext(ctx, program, "-test.run=^TestBackendInventoryCLILimitsNativeWorker$", "-test.count=1", "-test.v")
			worker.Env = backendCLINativeEnv(os.Environ(), backendCLINativeRole, "worker")
			worker.Env = backendCLINativeEnv(worker.Env, backendCLINativeCase, mode)
			worker.Env = backendCLINativeEnv(worker.Env, backendCLINativeState, dir)
			worker.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
			worker.Stdout, worker.Stderr = output, output
			worker.WaitDelay = 250 * time.Millisecond
			workerErr := worker.Run()
			// Failure recovery uses only recorded exact births. Ending the
			// outer PID namespace is the fallback for an unrecorded test fault.
			cleanupErr := backendCLINativeCleanup(dir)
			childrenErr := backendCLINativeNoChildren()
			if workerErr != nil || cleanupErr != nil || childrenErr != nil {
				t.Fatalf("private worker/cleanup failed: %v %v %v\n%s", workerErr, cleanupErr, childrenErr, output.data)
			}
			var proof backendCLINativeProof
			if err := backendCLINativeRead(filepath.Join(dir, "proof.json"), &proof); err != nil || proof.Case != mode || !proof.DirectWaitECHILD || !proof.FixtureCleanupECHILD || mode != "valid" && proof.ReturnedBytes != 0 || strings.HasPrefix(mode, "inherited-") && !proof.LeafAliveAfterRun {
				t.Fatal("missing actual fixture proof", proof, err)
			}
			t.Logf("actual CLI %s: elapsed=%dms returned=%d direct Wait=ECHILD leaf-alive-after-return=%t separate fixture cleanup=ECHILD", mode, proof.ElapsedMS, proof.ReturnedBytes, proof.LeafAliveAfterRun)
		}) {
			t.FailNow()
		}
	}
}
