//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const nfqws2ManagedNativeOptIn = "RAZVILKA_NFQWS_MANAGED_PROCESS_NATIVE"

type nfqws2ManagedNativeParentInput struct {
	StateRoot, ControlRoot, Program, ProgramSHA256, ID string
}

func TestNFQWSManagedProcessNativeEntry(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "nfqws-managed-helper" || arg == "nfqws-managed-daemon" || arg == "nfqws-managed-parent" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Skip("dedicated native fixture entry only")
	}
	args := os.Args[index:]
	switch args[0] {
	case "nfqws-managed-helper":
		if len(args) != 2 {
			os.Exit(8)
		}
		os.Exit(RunNFQWSManagedProcessSupervisor(args[1], filepath.Join(os.Getenv("RAZVILKA_DATAPLANE_STATE"), "runtime", "nfqws2"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE")))
	case "nfqws-managed-parent":
		if len(args) != 2 {
			os.Exit(8)
		}
		data, err := os.ReadFile(args[1])
		var input nfqws2ManagedNativeParentInput
		if err != nil || json.Unmarshal(data, &input) != nil {
			os.Exit(8)
		}
		a := NFQWS2Adapter{StateRoot: input.StateRoot}
		command := nfqws2ManagedNativeCommand(t, &a, input.ControlRoot, input.Program, input.ProgramSHA256, input.ID, "hold")
		_, err = a.runManagedNFQWSProcess(context.Background(), command, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"})
		if err != nil {
			os.Exit(9)
		}
		os.Exit(0)
	case "nfqws-managed-daemon":
		if len(args) != 2 {
			os.Exit(8)
		}
		switch args[1] {
		case "hold":
			for {
				time.Sleep(20 * time.Millisecond)
			}
		case "normal", "reject":
			time.Sleep(200 * time.Millisecond) // Keep birth/argv observable through Started fsync.
			if args[1] == "reject" {
				os.Exit(7)
			}
			os.Exit(0)
		case "detached":
			program, err := os.Executable()
			if err != nil {
				os.Exit(8)
			}
			child := exec.Command(program, "-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-daemon", "leaf")
			child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if child.Start() != nil {
				os.Exit(8)
			}
			_ = child.Process.Release() // Dedicated helper is the only descendant wait owner.
			time.Sleep(200 * time.Millisecond)
			os.Exit(0)
		case "leaf":
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}
	}
	os.Exit(8)
}

func nfqws2ManagedNativeGate(t *testing.T) string {
	t.Helper()
	if os.Getenv(nfqws2ManagedNativeOptIn) != "1" {
		t.Skip("exclusive isolated Linux harness: " + nfqws2ManagedNativeOptIn + "=1")
	}
	program, err := os.Executable()
	if err != nil || nfqws2ManagedProtected(program, false) != nil {
		t.Fatal("native test binary must be installed under a protected private test directory", program, err)
	}
	return program
}

func nfqws2ManagedNativeCommand(t *testing.T, a *NFQWS2Adapter, controlRoot, program, digest, id, mode string) nfqws2ManagedProcessCommand {
	t.Helper()
	parent, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := a.owner()
	if err != nil {
		t.Fatal(err)
	}
	control, present, err := operationgate.ReadSelfUpdateStop(context.Background(), controlRoot)
	if err != nil || !present || control.Stopped {
		t.Fatal("native control is unavailable", err)
	}
	return nfqws2ManagedProcessCommand{ID: id, StateRoot: a.StateRoot, Owner: owner, ControlRoot: controlRoot, InstallationID: control.InstallationID, Sequence: control.Sequence, Program: nfqws2ManagedFile{program, digest}, Args: []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-daemon", mode}, Parent: parent, Deadline: time.Now().Add(5 * time.Second).UTC()}
}

func nfqws2ManagedNativePrepare(t *testing.T, program, id, mode string) (*NFQWS2Adapter, nfqws2ManagedProcessCommand) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	a := &NFQWS2Adapter{StateRoot: filepath.Join(root, "dataplane", "runtime", "nfqws2")}
	if err := os.MkdirAll(a.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	controlRoot := filepath.Join(root, "self-update-control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(program)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return a, nfqws2ManagedNativeCommand(t, a, controlRoot, program, hex.EncodeToString(digest[:]), id, mode)
}

func nfqws2ManagedNativeRead(t *testing.T, a *NFQWS2Adapter) (nfqws2ManagedProcessLease, restorejournal.Image) {
	t.Helper()
	owner, err := a.owner()
	if err != nil {
		t.Fatal(err)
	}
	image, err := restorejournal.ReadFileImage(context.Background(), filepath.Join(a.StateRoot, nfqws2LeaseFile))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := nfqws2DecodeManagedLease(image, a.StateRoot, owner)
	if err != nil {
		t.Fatal(err)
	}
	return lease, image
}

func nfqws2ManagedNativeWait(t *testing.T, a *NFQWS2Adapter, terminal bool) nfqws2ManagedProcessLease {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		image, err := restorejournal.ReadFileImage(context.Background(), filepath.Join(a.StateRoot, nfqws2LeaseFile))
		owner, _ := a.owner()
		lease, decodeErr := nfqws2DecodeManagedLease(image, a.StateRoot, owner)
		if err == nil && decodeErr == nil {
			if terminal && (lease.Receipt.State == "reaped" || lease.Receipt.State == "not-started") {
				return lease
			}
			if !terminal && lease.Receipt.State == "running" && lease.Child.PID > 1 {
				return lease
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("managed process did not publish the expected durable phase")
	return nfqws2ManagedProcessLease{}
}

func TestNFQWSManagedProcessLifecycleNative(t *testing.T) {
	program := nfqws2ManagedNativeGate(t)
	for n, mode := range []string{"normal", "reject", "detached", "context-cancel", "control-stop", "wrong-parent", "parent-crash"} {
		t.Run(mode, func(t *testing.T) {
			daemonMode := mode
			if mode == "context-cancel" || mode == "control-stop" || mode == "parent-crash" || mode == "wrong-parent" {
				daemonMode = "hold"
			}
			a, command := nfqws2ManagedNativePrepare(t, program, fmt.Sprintf("%032x", n+1), daemonMode)
			if mode == "parent-crash" {
				input := nfqws2ManagedNativeParentInput{StateRoot: a.StateRoot, ControlRoot: command.ControlRoot, Program: program, ProgramSHA256: command.Program.SHA256, ID: command.ID}
				data, _ := json.Marshal(input)
				inputPath := filepath.Join(filepath.Dir(a.StateRoot), "parent-input.json")
				if err := os.WriteFile(inputPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				parent := exec.Command(program, "-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-parent", inputPath)
				if err := parent.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = parent.Process.Kill() })
				_ = nfqws2ManagedNativeWait(t, a, false)
				if err := parent.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				_ = parent.Wait()
				terminal := nfqws2ManagedNativeWait(t, a, true)
				if terminal.Acknowledged || !terminal.Receipt.WaitECHILD || !terminal.Receipt.DirectReaped || !terminal.Receipt.Cancelled || terminal.Receipt.ExitCode != 125 {
					t.Fatal("parent crash fabricated ACK or lost durable child settlement", terminal.Receipt)
				}
				if _, err := a.observeManagedNFQWSProcessInactive(context.Background()); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
					t.Fatal("unacknowledged crash became inactivity proof", err)
				}
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "wrong-parent" {
				command.Parent.Start = "1" + command.Parent.Start
			}
			type result struct {
				lease nfqws2ManagedProcessLease
				err   error
			}
			done := make(chan result, 1)
			go func() {
				lease, err := a.runManagedNFQWSProcess(ctx, command, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"})
				done <- result{lease, err}
			}()
			if mode == "context-cancel" || mode == "control-stop" {
				_ = nfqws2ManagedNativeWait(t, a, false)
				if _, err := a.observeManagedNFQWSProcessRunning(context.Background()); err != nil {
					t.Fatal("fresh exact helper/child birth/executable/argv observation failed", err)
				}
				if mode == "context-cancel" {
					cancel()
				} else if _, err := operationgate.RequestSelfUpdateStop(context.Background(), command.ControlRoot, command.ID, command.Sequence); err != nil {
					t.Fatal(err)
				}
			}
			completed := <-done
			if mode == "wrong-parent" {
				if !errors.Is(completed.err, ErrNFQWSManagedProcessUnknown) {
					t.Fatal("wrong parent was admitted", completed.err)
				}
				stored, _ := nfqws2ManagedNativeRead(t, a)
				if stored.Receipt.State != "intent" || stored.Acknowledged {
					t.Fatal("wrong-parent invocation acquired a receipt")
				}
				return
			}
			if mode == "context-cancel" {
				if !errors.Is(completed.err, context.Canceled) || errors.Is(completed.err, ErrNFQWSManagedProcessUnknown) {
					t.Fatal("known cancelled process outcome became ambiguous", completed.err)
				}
			} else if completed.err != nil {
				t.Fatal(completed.err)
			}
			lease, before := nfqws2ManagedNativeRead(t, a)
			if !nfqws2ManagedProcessSettled(lease) || lease.Child.PID <= 1 || lease.Child.Start == "" || lease.Child.ArgumentsSHA256 != components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args) {
				t.Fatal("actual child birth/argv/terminal ACK not proven", lease.Receipt, lease.Child)
			}
			if mode == "context-cancel" || mode == "control-stop" {
				if !lease.Receipt.Cancelled || lease.Receipt.ExitCode != 125 {
					t.Fatal("Stop/cancel was converted to a successful runtime result")
				}
			} else if mode == "reject" && lease.Receipt.ExitCode != 7 || (mode == "normal" || mode == "detached") && lease.Receipt.ExitCode != 0 {
				t.Fatal("terminal command exit was changed", lease.Receipt.ExitCode)
			}
			if mode == "detached" && lease.Receipt.Reaped < 2 {
				t.Fatal("detached child was not reaped by the sole helper")
			}
			if _, err := a.observeManagedNFQWSProcessInactive(context.Background()); err != nil {
				t.Fatal("fresh readback lost actual process settlement", err)
			}
			if err := a.VerifyRuntimeInactive(context.Background()); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
				t.Fatal("process proof bypassed the unfinished kernel owner", err)
			}
			_, after := nfqws2ManagedNativeRead(t, a)
			if string(before.Data) != string(after.Data) {
				t.Fatal("read-only observer changed the lifecycle image")
			}
			if _, err := a.runManagedNFQWSProcess(context.Background(), command, nil); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
				t.Fatal("retained session was replayed", err)
			}
		})
	}
}

// Optional ROOT-owned genuine review exercises the same producer with actual
// NFQWS executable/Lua/blob bytes and intercept=0. It grants no queue/scope proof.
func TestNFQWSManagedGenuineNoInterceptNative(t *testing.T) {
	program := nfqws2ManagedNativeGate(t)
	inputPath := os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW")
	if inputPath == "" {
		t.Skip("ROOT must supply an explicit protected genuine byte review")
	}
	var review struct {
		BinaryPath, BinarySHA256 string
		Assets                   []nfqws2ManagedFile
		BaseArguments            []string
	}
	data, err := os.ReadFile(inputPath)
	if err != nil || json.Unmarshal(data, &review) != nil || len(review.BaseArguments) == 0 {
		t.Fatal("explicit genuine review is invalid", err)
	}
	for _, arg := range review.BaseArguments {
		if !strings.HasPrefix(arg, "--lua-init=@") && !strings.HasPrefix(arg, "--blob=") {
			t.Fatal("genuine review must contain only ordered data asset bindings")
		}
	}
	a, command := nfqws2ManagedNativePrepare(t, program, strings.Repeat("f", 32), "normal")
	command.Program, command.Assets = nfqws2ManagedFile{review.BinaryPath, review.BinarySHA256}, review.Assets
	command.Args = append([]string{"--intercept=0"}, review.BaseArguments...)
	command.Args = append(command.Args, "--filter-tcp=443", "--lua-desync=fake:blob=0x00000000")
	lease, err := a.runManagedNFQWSProcess(context.Background(), command, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"})
	if err != nil || !nfqws2ManagedProcessSettled(lease) || !lease.Receipt.Started || lease.Receipt.Reaped < 1 {
		t.Fatal("genuine NFQWS did not produce exact durable kernel settlement", lease.Receipt, err)
	}
	t.Logf("actual reviewed NFQWS process receipt: exit=%d cancelled=%v reaped=%d ECHILD=%v ACK=%v; no queue/scope proof", lease.Receipt.ExitCode, lease.Receipt.Cancelled, lease.Receipt.Reaped, lease.Receipt.WaitECHILD, lease.Acknowledged)
	if _, err := a.observeManagedNFQWSProcessInactive(context.Background()); err != nil {
		t.Fatal("genuine process settlement did not survive fresh readback", err)
	}
	if err := a.VerifyRuntimeInactive(context.Background()); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
		t.Fatal("no-intercept process proof bypassed kernel ownership", err)
	}
}
