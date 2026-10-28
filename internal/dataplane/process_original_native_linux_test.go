//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func TestOriginalProcessNativeChild(t *testing.T) {
	index := slices.Index(os.Args, "--")
	if index < 0 || len(os.Args) != index+5 || os.Args[index+1] != "original-managed-child" {
		return
	}
	mode, address := os.Args[index+3], os.Args[index+4]
	if mode == "exit" {
		_ = os.WriteFile(os.Args[index+2]+".fixture-pid", []byte(strconv.Itoa(os.Getpid())), 0600)
		os.Exit(23)
	}
	interrupt := make(chan os.Signal, 2)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal("fixture listener", err)
	}
	defer listener.Close()
	for received := range interrupt {
		if mode == "kill" && received == os.Interrupt {
			continue
		}
		return
	}
}

func originalNativeFixture(t *testing.T, mode string) (*OriginalProcess, ProcessSpec, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "engine.json")
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := ProcessSpec{ID: "original-native-child", Binary: self,
		Args: []string{"-test.run=^TestOriginalProcessNativeChild$", "--", "original-managed-child", config, mode, address},
		Dir:  root, PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: true}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := (OSProcessController{}).StartOriginal(ctx, spec, address)
	if err != nil {
		t.Fatal("original fixture launch", err)
	}
	if !p.matches(spec, address) || p.matches(spec, "127.0.0.1:1") {
		t.Fatal("original launch/endpoint binding was lost")
	}
	other := spec
	other.ID += "-other"
	if p.matches(other, address) {
		t.Fatal("different process specification reused original token")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := p.StopAndJoin(cleanup); err != nil {
			t.Error("original fixture cleanup", err)
		}
	})
	for {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		select {
		case <-p.done:
			t.Fatal("original fixture exited before listening")
		case <-ctx.Done():
			t.Fatal("original fixture listener did not start")
		case <-time.After(10 * time.Millisecond):
		}
	}
	return p, spec, address
}

func TestOriginalProcessNativeActualWaitAndListenerAbsence(t *testing.T) {
	for _, mode := range []string{"interrupt", "kill", "external-term"} {
		t.Run(mode, func(t *testing.T) {
			p, spec, address := originalNativeFixture(t, mode)
			if mode == "external-term" {
				if err := p.child.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				select {
				case <-p.done:
				case <-time.After(5 * time.Second):
					t.Fatal("external TERM did not complete original Wait")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := p.StopAndJoin(ctx); err != nil {
				t.Fatal("owned cleanup not confirmed", err)
			}
			if p.matches(spec, address) {
				t.Fatal("terminal original token replayed as a fresh launch")
			}
			select {
			case <-p.done:
			default:
				t.Fatal("cleanup returned before original Wait")
			}
			if !xraySelectedTCPWaitResult(p.receipt.PID, p.state, p.waitErr) || originalProcessPIDAbsent(p.receipt.PID) != nil || originalProcessListenerAbsent(ctx, p.port) != nil {
				t.Fatal("cleanup lacked native terminal/absence proof")
			}
			if mode == "kill" {
				var exit *exec.ExitError
				status, ok := p.state.Sys().(syscall.WaitStatus)
				if !errors.As(p.waitErr, &exit) || exit.ProcessState != p.state || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("kill fixture did not exercise actual SIGKILL ExitError Wait")
				}
			}
			for _, path := range []string{spec.PIDPath, spec.PIDPath + routeidentity.ReceiptSuffix} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("confirmed cleanup retained live ownership file", err)
				}
			}
		})
	}
}

func TestOriginalProcessNativeStartupFailureReapsExactChild(t *testing.T) {
	for _, mode := range []string{"short-exit", "retain-error"} {
		t.Run(mode, func(t *testing.T) {
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "engine.json")
			if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			spec := ProcessSpec{ID: "original-startup-failure", Binary: self, Dir: root,
				PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: true,
				Args: []string{"-test.run=^TestOriginalProcessNativeChild$", "--", "original-managed-child", config, "exit", "127.0.0.1:19001"}}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			pid := 0
			if mode == "short-exit" {
				p, err := (OSProcessController{}).StartOriginal(ctx, spec, "127.0.0.1:19001")
				if err == nil {
					pid = p.receipt.PID
					select {
					case <-p.done:
					case <-ctx.Done():
						t.Fatal("short child did not exit")
					}
					if err := p.StopAndJoin(ctx); err != nil {
						t.Fatal("original natural exit could not close", err)
					}
				} else {
					raw, readErr := os.ReadFile(config + ".fixture-pid")
					if readErr != nil {
						t.Fatal("short fixture did not execute", readErr)
					}
					pid, _ = strconv.Atoi(string(raw))
				}
			} else {
				spec.Args[len(spec.Args)-2] = "interrupt"
				refused := errors.New("original retention refused")
				err := startManagedProcess(ctx, spec, func(command *exec.Cmd, receipt []byte) error {
					pid = command.Process.Pid
					if len(receipt) == 0 {
						t.Fatal("callback did not follow producer receipt")
					}
					return refused
				})
				if !errors.Is(err, refused) {
					t.Fatal("retention failure was hidden", err)
				}
			}
			if pid <= 1 || originalProcessPIDAbsent(pid) != nil {
				t.Fatal("startup failure left original child unreaped", pid)
			}
			for _, path := range []string{spec.PIDPath, spec.PIDPath + routeidentity.ReceiptSuffix} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("failed startup retained live ownership metadata", err)
				}
			}
		})
	}
}

func TestOriginalProcessNativeRefusalPreservesOriginalOwnership(t *testing.T) {
	for _, mode := range []string{"canceled", "config-change", "pid-file-replacement", "birth-receipt-change", "copied-token"} {
		t.Run(mode, func(t *testing.T) {
			p, spec, _ := originalNativeFixture(t, "interrupt")
			pid, err := os.ReadFile(spec.PIDPath)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.WriteFile(spec.MatchArg, []byte("{}"), 0600)
				_ = os.WriteFile(spec.PIDPath, pid, 0600)
				_ = os.WriteFile(spec.PIDPath+routeidentity.ReceiptSuffix, receipt, 0600)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			attempt := p
			switch mode {
			case "canceled":
				cancel()
			case "config-change":
				_ = os.WriteFile(spec.MatchArg, []byte("{\"changed\":true}"), 0600)
			case "pid-file-replacement":
				_ = os.WriteFile(spec.PIDPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600)
			case "birth-receipt-change":
				_ = os.WriteFile(spec.PIDPath+routeidentity.ReceiptSuffix, bytes.Replace(receipt, []byte(p.receipt.StartTicks), []byte("1"), 1), 0600)
			case "copied-token":
				clone := *p
				attempt = &clone
			}
			beforePID, _ := os.ReadFile(spec.PIDPath)
			beforeReceipt, _ := os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
			if err := attempt.StopAndJoin(ctx); err == nil {
				t.Fatal("uncertain ownership granted cleanup")
			}
			select {
			case <-p.done:
				t.Fatal("refused cleanup signaled original child")
			default:
			}
			afterPID, _ := os.ReadFile(spec.PIDPath)
			afterReceipt, _ := os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
			if !bytes.Equal(beforePID, afterPID) || !bytes.Equal(beforeReceipt, afterReceipt) {
				t.Fatal("refusal erased or replaced ownership metadata")
			}
		})
	}
}

func TestOriginalProcessNativeForeignListenerAfterWaitNeverGetsCleanup(t *testing.T) {
	p, spec, address := originalNativeFixture(t, "interrupt")
	if err := p.child.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("original Wait unavailable")
	}
	foreign, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { foreign.Close() })
	pidBefore, _ := os.ReadFile(spec.PIDPath)
	receiptBefore, _ := os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.StopAndJoin(ctx); err == nil {
		t.Fatal("original Wait hid a newly occupied listener")
	}
	pidAfter, _ := os.ReadFile(spec.PIDPath)
	receiptAfter, _ := os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
	if !bytes.Equal(pidBefore, pidAfter) || !bytes.Equal(receiptBefore, receiptAfter) || originalProcessPIDAbsent(os.Getpid()) == nil {
		t.Fatal("foreign/current PID was treated as absent or metadata erased")
	}
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal("foreign listener was touched", err)
	}
	connection.Close()
}
