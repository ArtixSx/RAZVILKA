//go:build linux

package operationgate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNativeSelfUpdateControlChild(t *testing.T) {
	mode := os.Getenv("RAZVILKA_CONTROL_TEST_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("RAZVILKA_CONTROL_TEST_ROOT")
	if mode == "hold-admission" {
		err := WithSelfUpdateEffectAdmission(context.Background(), path, controlTestID, 1, "start-candidate-panel", func() error {
			fmt.Println("admitted")
			var release [1]byte
			_, err := io.ReadFull(os.Stdin, release[:])
			return err
		})
		if err != nil {
			os.Exit(72)
		}
		os.Exit(0)
	}
	if mode == "crash-stop" {
		boundary := os.Getenv("RAZVILKA_CONTROL_TEST_BOUNDARY")
		_, _ = requestSelfUpdateStop(context.Background(), path, controlTestID, 12, func(at string) error {
			if at == boundary {
				os.Exit(73)
			}
			return nil
		})
		os.Exit(74)
	}
	os.Exit(75)
}

func TestNativeSelfUpdateStopCrossProcessAdmission(t *testing.T) {
	path := controlTestRoot(t)
	if _, err := InitializeSelfUpdateControl(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeSelfUpdateControlChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_CONTROL_TEST_MODE=hold-admission", "RAZVILKA_CONTROL_TEST_ROOT="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			cancel()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "admitted\n" {
		t.Fatal("child never obtained kernel admission", line, err)
	}
	ack := make(chan error, 1)
	go func() { _, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12); ack <- err }()
	select {
	case err := <-ack:
		t.Fatal("cross-process Stop bypassed active admission", err)
	case <-time.After(25 * time.Millisecond):
	}
	if _, err = stdin.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	joined = true
	if err = <-ack; err != nil {
		t.Fatal(err)
	}
	late := false
	if err = WithSelfUpdateEffectAdmission(ctx, path, controlOtherID, 1, "late-child", func() error { late = true; return nil }); !errors.Is(err, ErrSelfUpdateStopped) || late {
		t.Fatal("Stop allowed later admitted child", late, err)
	}
}

func TestNativeSelfUpdateStopCrashBoundariesPreserveInhibition(t *testing.T) {
	for _, boundary := range []string{"stop-current-durable", "stop-intent-durable"} {
		t.Run(boundary, func(t *testing.T) {
			path := controlTestRoot(t)
			if _, err := InitializeSelfUpdateControl(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeSelfUpdateControlChild$")
			cmd.Env = append(os.Environ(), "RAZVILKA_CONTROL_TEST_MODE=crash-stop", "RAZVILKA_CONTROL_TEST_ROOT="+path, "RAZVILKA_CONTROL_TEST_BOUNDARY="+boundary)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatal("crash boundary not reached", err)
			}
			called := false
			if err = WithSelfUpdateEffectAdmission(ctx, path, controlTestID, 1, "start-rollback-panel", func() error { called = true; return nil }); err == nil || called {
				t.Fatal("crashed revocation authorized rollback startup", err)
			}
			r, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12)
			if err != nil || !r.Stopped || r.Sequence != 2 {
				t.Fatal("matching crash retry lost control epoch", r, err)
			}
		})
	}
}
