//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestInstallerHelperSpawnFixture(t *testing.T) {
	if os.Getenv("RAZVILKA_INSTALLER_HANDOFF_FIXTURE") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("RAZVILKA_INSTALLER_HANDOFF_MARKER"), []byte("actual child"), 0600); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestNativeInstallerHelperActualStartSharesStopAdmission(t *testing.T) {
	for _, kind := range []string{"allowed", "stop", "nil", "no-effect", "cancel", "post-start-error"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			control := filepath.Join(base, "control")
			ready, err := operationgate.InitializeSelfUpdateControl(context.Background(), control)
			if err != nil {
				t.Fatal(err)
			}
			id := "0123456789abcdef0123456789abcdef"
			marker := filepath.Join(base, "spawned")
			cmd := exec.Command(os.Args[0], "-test.run=^TestInstallerHelperSpawnFixture$")
			cmd.Env = append(os.Environ(), "RAZVILKA_INSTALLER_HANDOFF_FIXTURE=1", "RAZVILKA_INSTALLER_HANDOFF_MARKER="+marker)
			ctx := context.Background()
			admission := func(begin func() error) error {
				if kind == "stop" {
					if _, err := operationgate.RequestSelfUpdateStop(ctx, control, id, 7); err != nil {
						return err
					}
				}
				if kind == "no-effect" {
					return nil
				}
				if err := operationgate.WithSelfUpdateEffectAdmission(ctx, control, id, ready.InstallationID, ready.Sequence, installerHelperEffect, begin); err != nil {
					return err
				}
				if kind == "post-start-error" {
					_, err := operationgate.RequestSelfUpdateStop(ctx, control, id, 7)
					return errors.Join(operationgate.ErrSelfUpdateStopped, err)
				}
				return nil
			}
			if kind == "nil" {
				admission = nil
			}
			if kind == "cancel" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			pid, done, err := startInstallerHelperCommand(ctx, cmd, admission)
			if kind == "allowed" || kind == "post-start-error" {
				if pid <= 1 || done == nil || (kind == "allowed" && err != nil) || (kind == "post-start-error" && !errors.Is(err, ErrHandoffUncertain)) {
					t.Fatal("actual helper custody was lost", pid, done, err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("sole parent Wait did not join")
				}
				if data, err := os.ReadFile(marker); err != nil || string(data) != "actual child" {
					t.Fatal(string(data), err)
				}
				return
			}
			if err == nil || pid != 0 || done != nil || cmd.Process != nil {
				t.Fatal("refused admission executed actual Start", pid, done, cmd.Process, err)
			}
			if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused helper wrote a marker", err)
			}
		})
	}
}
