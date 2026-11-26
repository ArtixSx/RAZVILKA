package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallerHelperApplyRequiresSealedStartAdmission(t *testing.T) {
	for _, kind := range []string{"allowed", "nil", "missing-review", "changed-review", "stop", "no-effect", "post-start-error"} {
		t.Run(kind, func(t *testing.T) {
			_, u, review := fileAdapterFixture(t)
			job := u.Snapshot()
			spawned, admitted := 0, false
			stop := errors.New("revoked by exact CORE Stop")
			u.FileEffectAdmission = func(ctx context.Context, id, installation string, sequence uint64, action, effect string, begin func() error) error {
				admitted = true
				if id != review.ID || installation != review.AuthorityInstallationID || sequence != review.AuthoritySequence || action != "start/live" || effect != "installer-helper" {
					t.Fatal("helper admission did not use the sealed authority", id, installation, sequence, action, effect)
				}
				if kind == "stop" {
					return stop
				}
				if kind == "no-effect" {
					return nil
				}
				if err := begin(); err != nil {
					return err
				}
				if kind == "post-start-error" {
					return stop
				}
				return nil
			}
			u.launch = func(ctx context.Context, id string, admission func(func() error) error) (int, error) {
				pid := 0
				err := admission(func() error { spawned++; pid = 345678; return nil })
				if err == nil && pid == 0 {
					err = ErrFileProtocol
				}
				return pid, err
			}
			switch kind {
			case "nil":
				u.FileEffectAdmission = nil
			case "missing-review":
				if err := os.Remove(filepath.Join(u.Directory, job.ID, "file-review.json")); err != nil {
					t.Fatal(err)
				}
			case "changed-review":
				if err := os.WriteFile(filepath.Join(u.Directory, job.ID, "file-review.json"), []byte("third image"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture")
			if kind == "allowed" {
				if err != nil || spawned != 1 || !admitted || result.HelperPID != 345678 {
					t.Fatal(result, spawned, admitted, err)
				}
				return
			}
			if kind == "post-start-error" {
				if !errors.Is(err, ErrHandoffUncertain) || spawned != 1 || result.HelperPID != 345678 || result.State != "requires-review" || !u.StartupPending() {
					t.Fatal("actual start was mislabeled as not started", result, spawned, err)
				}
				if _, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture"); !errors.Is(err, ErrBusy) {
					t.Fatal("uncertain helper was replayed", err)
				}
				return
			}
			if err == nil || spawned != 0 || result.HelperPID != 0 {
				t.Fatal("refusal started a helper", result, spawned, admitted, err)
			}
		})
	}
}
