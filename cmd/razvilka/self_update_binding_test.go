package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSelfUpdateAuthorityReviewSealsExistingInstallationAndNeverClearsStop(t *testing.T) {
	ctx, root := context.Background(), filepath.Join(t.TempDir(), "control")
	review := selfUpdateAuthorityReview(root)
	id := strings.Repeat("a", 32)
	for _, bad := range []string{"", strings.ToUpper(id), id + "0"} {
		if _, err := review(ctx, bad); err == nil {
			t.Fatal("invalid review identity accepted")
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("refused review created control state", err)
	}
	first, err := review(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	again, err := review(ctx, id)
	if err != nil || again != first {
		t.Fatal("authority review refreshed identity", again, err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, root, id, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := review(ctx, id); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("review cleared Stop", err)
	}
	current, present, err := operationgate.ReadSelfUpdateStop(ctx, root)
	if err != nil || !present || !current.Stopped || current.InstallationID != first.InstallationID || current.Sequence != first.Sequence+1 {
		t.Fatal(current, present, err)
	}
}

type selfUpdateObserverFixture struct {
	calls  int
	err    error
	cancel context.CancelFunc
}

func (f *selfUpdateObserverFixture) VerifyRuntimeInactive(context.Context) error {
	f.calls++
	if f.cancel != nil {
		f.cancel()
	}
	return f.err
}

func TestSelfUpdateRuntimeObserverMissingUnknownAndCanceledNeverPass(t *testing.T) {
	if verifySelfUpdateRuntimeInactive(context.Background(), nil) == nil {
		t.Fatal("missing runtime owner accepted")
	}
	unknown := errors.New("unsettled owned runtime")
	f := &selfUpdateObserverFixture{err: unknown}
	if err := verifySelfUpdateRuntimeInactive(context.Background(), f); !errors.Is(err, unknown) || f.calls != 1 {
		t.Fatal("unknown runtime accepted", err, f.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f = &selfUpdateObserverFixture{cancel: cancel}
	if err := verifySelfUpdateRuntimeInactive(ctx, f); !errors.Is(err, context.Canceled) || f.calls != 1 {
		t.Fatal("canceled observation accepted", err, f.calls)
	}
	f = &selfUpdateObserverFixture{}
	if err := verifySelfUpdateRuntimeInactive(ctx, f); !errors.Is(err, context.Canceled) || f.calls != 0 {
		t.Fatal("canceled caller entered owner", err, f.calls)
	}
}

func TestSelfUpdateExactStartupArgumentsRefuseBeforeBootstrap(t *testing.T) {
	for _, args := range [][]string{{"-self-update-job", strings.Repeat("a", 32)}, {"-self-update-helper-pid", "2"}, {"-self-update-job", strings.Repeat("a", 32), "-self-update-helper-pid", "1"}, {"-self-update-job", strings.Repeat("a", 32), "-self-update-helper-pid", "2"}} {
		work := t.TempDir()
		configPath, stage := filepath.Join(work, "config.json"), filepath.Join(work, "stage")
		args = append(args, "-config", configPath, "-stage", stage, "-self-update-installation", filepath.Join(work, "installation"), "-self-update-file-state", filepath.Join(work, "files"), "-self-update-helper-state", filepath.Join(work, "helper"), "-self-update-control-state", filepath.Join(work, "control"))
		if output, err := selfUpdateMainSubprocess(t, args...); err == nil {
			t.Fatal("unproven startup admitted", string(output))
		}
		for _, path := range []string{configPath, stage, filepath.Join(work, "control"), filepath.Join(work, "files"), filepath.Join(work, "helper")} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("refused startup created state", path, err)
			}
		}
	}
}

func TestSelfUpdateEarlyCommandsValidateBeforeOrdinaryBootstrap(t *testing.T) {
	for _, args := range [][]string{{"self-update-command-helper"}, {"self-update-command-helper", "bad"}, {"self-update-runtime-quiesce"}, {"self-update-runtime-quiesce", "bad", "01", "2"}, {"self-update-runtime-quiesce", "bad", "1", "02"}, {"self-update-runtime-quiesce", "bad", "1", "1"}} {
		if handled, code := runCommand(args); !handled || code != 2 {
			t.Fatal("invalid command fell through to bootstrap", args, handled, code)
		}
	}
}
