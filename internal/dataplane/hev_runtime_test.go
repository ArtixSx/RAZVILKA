package dataplane

import (
	"context"
	"errors"
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
