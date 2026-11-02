package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
)

type hevVersionFixtureRunner func(context.Context, string, ...string) ([]byte, error)

func (r hevVersionFixtureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r(ctx, name, args...)
}
func TestHEVVersionPreflightDoesNotPromoteOldOrUnreviewedRuntime(t *testing.T) {
	for _, version := range []string{"2.14.3", "2.15.0", "2.16.0", "2.17.1", "2.19.3", "unknown"} {
		t.Run(version, func(t *testing.T) {
			a := hevFixture(t)
			calls := 0
			a.Runner = hevVersionFixtureRunner(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
				calls++
				if len(args) != 1 || args[0] != "--version" {
					t.Fatal("version check tried starting TUN")
				}
				return []byte("hev CONFIG_PATH\nVersion: " + version + " fixture\n"), nil
			})
			err := a.preflightHEVRuntime(context.Background())
			if (err == nil) != (version == "2.17.1") || calls != 1 {
				t.Fatal("wrong runtime accepted or command shape changed", err)
			}
		})
	}
}
func TestHEVVersionPreflightHonorsCancellationAndCommandFailure(t *testing.T) {
	a := hevFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	a.Runner = hevVersionFixtureRunner(func(context.Context, string, ...string) ([]byte, error) {
		cancel()
		return []byte("Version: 2.17.1 fixture\n"), nil
	})
	if err := a.preflightHEVRuntime(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("late version result revived cancellation", err)
	}
	a.Runner = hevVersionFixtureRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Version: 2.17.1 fixture\n"), errors.New("program execution failed")
	})
	if err := a.preflightHEVRuntime(context.Background()); err == nil {
		t.Fatal("version text disguised command failure")
	}
}

func TestHEVManagedOwnerRecheckedOnEveryStartAttempt(t *testing.T) {
	a := hevFixture(t)
	checks, commands := 0, 0
	refused := errors.New("original pinned receipt changed")
	a.hevInstalledCheck = func(context.Context) error { checks++; return refused }
	a.Runner = hevVersionFixtureRunner(func(context.Context, string, ...string) ([]byte, error) {
		commands++
		return []byte("Version: 2.17.1 fixture"), nil
	})
	for i := 0; i < 3; i++ {
		if err := a.startOwnedSidecar(context.Background()); !errors.Is(err, refused) {
			t.Fatal("start skipped original component admission", err)
		}
	}
	if checks != 3 || commands != 0 {
		t.Fatal("refused owner executed binary or cached result", checks, commands)
	}
}

func TestHEVStartRefusesOppositeBackendRestoredImage(t *testing.T) {
	a := hevFixture(t)
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.sidecarConfigPath(), []byte(`{"inbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	commands := 0
	a.Runner = hevVersionFixtureRunner(func(context.Context, string, ...string) ([]byte, error) { commands++; return nil, nil })
	if err := a.startOwnedSidecar(context.Background()); err == nil || commands != 0 {
		t.Fatal("opposite-kind retained image launched", err, commands)
	}
	b, err := a.hevConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.sidecarConfigPath(), b, 0600); err != nil {
		t.Fatal(err)
	}
	a.SidecarKind, a.SidecarBin = "", ""
	if err := a.startOwnedSidecar(context.Background()); err == nil || commands != 0 {
		t.Fatal("HEV retained image launched by standard backend", err, commands)
	}
}

func TestHEVPreflightRejectsLateOriginalReceiptChange(t *testing.T) {
	a := hevFixture(t)
	checks := 0
	late := errors.New("original receipt changed after command")
	a.hevInstalledCheck = func(context.Context) error {
		checks++
		if checks == 2 {
			return late
		}
		return nil
	}
	if err := a.preflightHEVRuntime(context.Background()); !errors.Is(err, late) || checks != 2 {
		t.Fatal("version result outlived original receipt", err, checks)
	}
}
