//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Tests actual fd execution, exact recipe admission and sole-child joining.
// The copied image's CLI response is synthetic; no actual HTTP/LKG is claimed.
func TestNativeSelfUpdateLiveProbeActualAdmissionAndJoin(t *testing.T) {
	for _, effect := range []string{fileLiveVersionEffect, fileLiveHealthEffect} {
		for _, kind := range []string{"allowed", "stop", "cancel", "no-begin", "post-start-error", "post-start-stop", "stop-while-running"} {
			if kind == "stop-while-running" && effect != fileLiveVersionEffect {
				continue // only the held version fixture deliberately remains alive
			}
			t.Run(effect+"/"+kind, func(t *testing.T) {
				a, _, review, profile := nativeFileFixture(t, "delayed")
				imagePath := filepath.Join(a.installation, "bin/razvilka")
				if kind == "stop-while-running" {
					data, err := os.ReadFile(imagePath)
					if err != nil {
						t.Fatal(err)
					}
					imagePath = filepath.Join(t.TempDir(), "live-probe-hold.bin")
					if err := os.WriteFile(imagePath, data, 0700); err != nil {
						t.Fatal(err)
					}
				}
				image, err := os.Open(imagePath)
				if err != nil {
					t.Fatal(err)
				}
				defer image.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				type originalKey struct{}
				ctx = context.WithValue(ctx, originalKey{}, review.ID)
				deadline, _ := ctx.Deadline()
				started, stopDone := make(chan struct{}), make(chan error, 1)
				if kind == "stop-while-running" {
					go func() {
						select {
						case <-started:
							_, err := operationgate.RequestSelfUpdateStop(ctx, profile.Control, review.ID, review.Revision)
							stopDone <- err
						case <-ctx.Done():
							stopDone <- ctx.Err()
						}
					}()
				}
				original := a.admission
				starts := 0
				a.admission = func(actualCtx context.Context, id, installation string, sequence uint64, action, actualEffect string, begin func() error) error {
					actualDeadline, bounded := actualCtx.Deadline()
					if actualCtx.Err() != nil || !bounded || actualDeadline != deadline || actualCtx.Value(originalKey{}) != review.ID || id != review.ID || installation != review.AuthorityInstallationID || sequence != review.AuthoritySequence || action != "start/live" || actualEffect != effect {
						t.Fatal("probe lost exact sealed authority")
					}
					if kind == "no-begin" {
						return nil
					}
					if err := original(actualCtx, id, installation, sequence, action, actualEffect, func() error {
						if err := begin(); err != nil {
							return err
						}
						starts++
						if kind == "stop-while-running" {
							close(started)
						}
						return nil
					}); err != nil {
						return err
					}
					if kind == "post-start-error" || kind == "post-start-stop" {
						_, err := operationgate.RequestSelfUpdateStop(actualCtx, profile.Control, id, review.Revision)
						if kind == "post-start-stop" {
							return err
						}
						return errors.Join(operationgate.ErrSelfUpdateStopped, err)
					}
					return nil
				}
				if kind == "stop" {
					if _, err := operationgate.RequestSelfUpdateStop(ctx, profile.Control, review.ID, review.Revision); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "cancel" {
					cancel()
				}
				endpoint, pid, wanted := "", 0, "fixture-probe\n"
				if effect == fileLiveHealthEffect {
					endpoint, pid, wanted = "http://127.0.0.1:8787/api/v1/status", os.Getpid(), "healthy: fixture-probe\n"
				}
				output, err := a.runFileLiveProbe(ctx, review.ID, image, effect, endpoint, pid)
				if kind == "allowed" {
					if err != nil || output != wanted || starts != 1 {
						t.Fatal("actual admitted held-fd probe", output, starts, err)
					}
				} else if err == nil || output != "" || starts != map[bool]int{false: 0, true: 1}[kind == "post-start-error" || kind == "post-start-stop" || kind == "stop-while-running"] {
					t.Fatal("refused probe escaped or lost custody", output, starts, err)
				}
				if kind == "stop-while-running" {
					select {
					case err := <-stopDone:
						if err != nil {
							t.Fatal("actual Stop while probe running", err)
						}
					case <-ctx.Done():
						t.Fatal("actual Stop failed to join probe before deadline", ctx.Err())
					}
				}
				if kind != "cancel" && ctx.Err() != nil {
					t.Fatal("deadline became negative admission evidence", ctx.Err())
				}
				var status syscall.WaitStatus
				if _, err := syscall.Wait4(-1, &status, syscall.WNOHANG|syscall.WALL, nil); err != syscall.ECHILD {
					t.Fatal("direct probe child not joined", err)
				}
			})
		}
	}
}
