package operationgate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelfUpdateStoppedCompensationCannotRestoreStartAuthority(t *testing.T) {
	ctx, path := context.Background(), controlTestRoot(t)
	ready, err := InitializeSelfUpdateControl(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, selfControlCurrent))
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range []string{"command-worker-stop-old-panel", "command-child-stop-candidate-panel", "command-worker-quiesce-old-runtime", "command-child-quiesce-old-runtime", "candidate-known-absent-pid", "rollback-file-0", "rollback-file-5", "command-worker-restore-private-state", "rollback-private-nodes"} {
		action := "replace-to-rollback"
		if strings.HasPrefix(effect, "command-") && effect != "command-worker-restore-private-state" || effect == "candidate-known-absent-pid" {
			action = "stop-owned"
		}
		called := false
		err := WithSelfUpdateStoppedEffectAdmission(ctx, path, controlTestID, ready.InstallationID, ready.Sequence, 12, action, effect, func() error { called = true; return nil })
		if err != nil || !called {
			t.Fatalf("matching compensation %s: %v", effect, err)
		}
	}
	for _, test := range []struct{ action, effect string }{
		{"start/live", "candidate-known-absent-pid"},
		{"replace-to-rollback", "candidate-known-absent-pid"},
		{"bootstrap-offline", "candidate-known-absent-pid"},
		{"read/observe", "candidate-known-absent-pid"},
		{"stop-owned", "candidate-known-absent-pid-extra"},
		{"stop-owned", "candidate-known-absent-pid-../other"},
		{"start/live", "command-child-start-candidate-panel"},
		{"start/live", "command-child-start-rollback-panel"},
		{"replace-to-rollback", "install-file-0"},
		{"stop-owned", "rollback-file-0"},
		{"replace-to-rollback", "command-worker-quiesce-old-runtime"},
		{"replace-to-rollback", "rollback-file-6"},
		{"replace-to-rollback", "rollback-file-00"},
		{"replace-to-rollback", "rollback-private-../nodes"},
		{"read/observe", "rollback-file-0"},
	} {
		called := false
		err := WithSelfUpdateStoppedEffectAdmission(ctx, path, controlTestID, ready.InstallationID, ready.Sequence, 12, test.action, test.effect, func() error { called = true; return nil })
		if !errors.Is(err, ErrSelfUpdateStopChanged) || called {
			t.Fatalf("class borrowed authority: %+v %v", test, err)
		}
	}
	called := false
	if err := WithSelfUpdateEffectAdmission(ctx, path, controlTestID, ready.InstallationID, ready.Sequence, "start-rollback-panel", func() error { called = true; return nil }); !errors.Is(err, ErrSelfUpdateStopped) || called {
		t.Fatal("compensation revived Start", err)
	}
	after, err := os.ReadFile(filepath.Join(path, selfControlCurrent))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("compensation rewrote Stop", err)
	}
}

func TestSelfUpdateStoppedCompensationRequiresExactSealedIdentityAndIntent(t *testing.T) {
	for _, change := range []string{"running", "transaction", "installation", "epoch", "current-epoch", "revision", "missing-intent", "canceled"} {
		t.Run(change, func(t *testing.T) {
			ctx, path := context.Background(), controlTestRoot(t)
			ready, err := InitializeSelfUpdateControl(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if change != "running" {
				if _, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12); err != nil {
					t.Fatal(err)
				}
			}
			id, installation, epoch, revision := controlTestID, ready.InstallationID, ready.Sequence, uint64(12)
			switch change {
			case "transaction":
				id = controlOtherID
			case "installation":
				installation = controlOtherID
			case "epoch":
				epoch = 9
			case "current-epoch":
				epoch++
			case "revision":
				revision++
			case "missing-intent":
				if err := os.Remove(filepath.Join(path, "stop-"+controlTestID+".json")); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			for _, effect := range []struct{ action, id string }{{"replace-to-rollback", "rollback-file-0"}, {"stop-owned", "candidate-known-absent-pid"}} {
				called := false
				err = WithSelfUpdateStoppedEffectAdmission(ctx, path, id, installation, epoch, revision, effect.action, effect.id, func() error { called = true; return nil })
				if err == nil || called {
					t.Fatal("unproven compensation admitted", effect, err)
				}
			}
		})
	}
}
