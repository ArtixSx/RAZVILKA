//go:build linux

package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nfqwsProcessFixtureInput struct {
	Command                       NFQWSSupervisionCommand
	Mode, ResultPath, StartedPath string
}

type nfqwsProcessFixtureResult struct {
	Receipt NFQWSSupervisionReceipt
	Output  []byte
}

func TestNFQWSSupervisionReadIdentity(t *testing.T) {
	identity, err := ReadNFQWSSupervisionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadNFQWSSupervisionProcessIdentity(os.Getpid())
	if err != nil || read != identity || identity.PID != os.Getpid() || identity.Start == "" || !validBootID(identity.BootID) {
		t.Fatalf("identity=%+v read=%+v err=%v", identity, read, err)
	}
	for _, pid := range []int{-1, 0, 1} {
		if _, err := ReadNFQWSSupervisionProcessIdentity(pid); !errors.Is(err, ErrNFQWSSupervisionUnknown) {
			t.Fatalf("PID %d: %v", pid, err)
		}
	}
}

// These fixed Go process fixtures test kernel lifecycle evidence only. They do
// not execute NFQWS and cannot establish genuine CLI/Lua compatibility.
func TestNFQWSSupervisionProcessEntry(t *testing.T) {
	if len(os.Args) < 4 || os.Args[2] != "nfqws-process-entry" {
		return
	}
	mode := os.Args[3]
	if mode == "helper" {
		if len(os.Args) != 5 {
			os.Exit(81)
		}
		data, err := os.ReadFile(os.Args[4])
		var input nfqwsProcessFixtureInput
		if err != nil || json.Unmarshal(data, &input) != nil {
			os.Exit(82)
		}
		ctx, cancel := context.WithDeadline(context.Background(), input.Command.Deadline)
		defer cancel()
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(signals)
		go func() {
			select {
			case <-signals:
				cancel()
			case <-ctx.Done():
			}
		}()
		hooks := nfqwsTestHooks()
		hooks.Armed = func(NFQWSSupervisionIdentity) error {
			if input.Mode == "armed-crash" {
				os.Exit(23)
			}
			return nil
		}
		hooks.Started = func(int) error {
			if input.Mode == "started-write-error" {
				return errors.New("fixture durable Started failure")
			}
			return os.WriteFile(input.StartedPath, []byte("started"), 0600)
		}
		hooks.Result = func(receipt NFQWSSupervisionReceipt, output []byte) error {
			if input.Mode == "result-write-error" {
				return errors.New("fixture Result failure")
			}
			data, err := json.Marshal(nfqwsProcessFixtureResult{receipt, output})
			if err != nil {
				return err
			}
			return os.WriteFile(input.ResultPath, data, 0600)
		}
		if input.Mode == "admission-denied" {
			hooks.StartAdmission = func(func() error) error { return errors.New("fixture Stop admission denied") }
		}
		if input.Mode == "admission-skipped" {
			hooks.StartAdmission = func(func() error) error { return nil }
		}
		if input.Mode == "stop-after-start" {
			hooks.StopCheck = func() error {
				if _, err := os.Stat(input.StartedPath); err == nil {
					return errors.New("fixture sealed Stop authority changed")
				}
				return nil
			}
		}
		_, err = RunNFQWSSupervision(ctx, input.Command, hooks)
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if mode == "zero" {
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("a", 12000)+"fixture-tail")
		os.Exit(0)
	}
	if mode == "reject" {
		os.Exit(7)
	}
	if mode == "sleeper" {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}
	if mode == "long-sleeper" {
		time.Sleep(8 * time.Second) // watchdog even if a fixture helper crashes.
		os.Exit(0)
	}
	if mode == "detached" || mode == "cancel-detached" {
		program, err := os.Executable()
		if err != nil {
			os.Exit(84)
		}
		leaf := "sleeper"
		if mode == "cancel-detached" {
			leaf = "long-sleeper"
		}
		cmd := exec.Command(program, "-test.run=^TestNFQWSSupervisionProcessEntry$", "nfqws-process-entry", leaf)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = []string{"PATH=/opt/bin:/opt/sbin:/usr/bin:/bin", "LANG=C", "TZ=UTC"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if cmd.Start() != nil {
			os.Exit(85)
		}
		_ = cmd.Process.Release()
		if len(os.Args) == 5 && os.WriteFile(os.Args[4], []byte("descendant-started"), 0600) != nil {
			os.Exit(86)
		}
		os.Exit(0)
	}
	os.Exit(87)
}

func TestNFQWSSupervisionKernelReceipts(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQWS_PROCESS_FIXTURE") != "1" {
		t.Skip("root-only opt-in fixed Go process fixtures; no genuine NFQWS CLI/Lua execution")
	}
	for _, mode := range []string{"zero", "reject", "detached", "cancel-detached", "deadline-detached", "stop-after-start", "started-write-error", "admission-denied", "admission-skipped", "result-write-error", "armed-crash", "wrong-parent-birth", "not-private-session"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			program, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			parent, err := ReadNFQWSSupervisionIdentity()
			if err != nil {
				t.Fatal(err)
			}
			leaf := mode
			if mode != "reject" && mode != "detached" && mode != "cancel-detached" {
				leaf = "zero"
			}
			if mode == "deadline-detached" {
				leaf = "cancel-detached"
			}
			marker := filepath.Join(dir, "descendant-started")
			input := nfqwsProcessFixtureInput{Command: NFQWSSupervisionCommand{Program: program, Args: []string{"-test.run=^TestNFQWSSupervisionProcessEntry$", "nfqws-process-entry", leaf, marker}, BootID: parent.BootID, ParentStart: parent.Start, ParentPID: parent.PID, CommandSHA256: strings.Repeat("a", 64), Deadline: time.Now().Add(5 * time.Second)}, Mode: mode, ResultPath: filepath.Join(dir, "result.json"), StartedPath: filepath.Join(dir, "started")}
			if mode == "wrong-parent-birth" {
				input.Command.ParentStart = "18446744073709551615"
			}
			if mode == "deadline-detached" {
				input.Command.Deadline = time.Now().Add(500 * time.Millisecond)
			}
			data, _ := json.Marshal(input)
			inputPath := filepath.Join(dir, "input.json")
			if err := os.WriteFile(inputPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(program, "-test.run=^TestNFQWSSupervisionProcessEntry$", "nfqws-process-entry", "helper", inputPath)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if mode == "not-private-session" {
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }() // parent waits only its owned helper.
			if mode == "cancel-detached" {
				limit := time.Now().Add(2 * time.Second)
				for {
					if _, err := os.Stat(marker); err == nil {
						break
					}
					if !time.Now().Before(limit) {
						_ = cmd.Process.Signal(syscall.SIGTERM)
						t.Fatal("descendant fixture did not start")
					}
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(30 * time.Millisecond) // direct child has exited zero.
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatal("owned helper exceeded fixture bound")
			}
			data, err = os.ReadFile(input.ResultPath)
			if mode == "result-write-error" || mode == "armed-crash" || mode == "wrong-parent-birth" || mode == "not-private-session" {
				if !os.IsNotExist(err) {
					t.Fatalf("unexpected accepted terminal file: %v %s", err, data)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var result nfqwsProcessFixtureResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			r := result.Receipt
			if !r.WaitECHILD || r.PID <= 1 || r.Group != r.PID || r.CommandSHA256 != input.Command.CommandSHA256 {
				t.Fatalf("missing exact terminal evidence: %+v", r)
			}
			if mode == "admission-denied" || mode == "admission-skipped" {
				if r.State != "not-started" || r.Started || r.DirectReaped || r.ChildPID != 0 || r.ExitCode == 0 {
					t.Fatalf("spawn despite refusal: %+v", r)
				}
				return
			}
			if r.State != "reaped" || !r.Started || !r.DirectReaped || r.Reaped < 1 {
				t.Fatalf("incomplete child accounting: %+v", r)
			}
			if mode == "detached" && r.Reaped < 2 {
				t.Fatalf("detached descendant was not accounted: %+v", r)
			}
			if mode == "zero" || mode == "detached" {
				if r.ExitCode != 0 || r.Cancelled {
					t.Fatalf("expected ordinary kernel completion: %+v", r)
				}
			} else if mode == "reject" {
				if r.ExitCode != 7 || r.Cancelled {
					t.Fatalf("expected known rejection: %+v", r)
				}
			} else if r.ExitCode != 125 || !r.Cancelled {
				t.Fatalf("cleanup became success: %+v", r)
			}
			if mode == "zero" && (len(result.Output) != 8192 || !strings.HasSuffix(string(result.Output), "fixture-tail")) {
				t.Fatalf("unbounded/missing tail: %d", len(result.Output))
			}
		})
	}
}
