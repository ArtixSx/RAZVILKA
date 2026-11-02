package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestHEVGuardedForwardCASRefusalCompensatesWithoutNewAdmission(t *testing.T) {
	for _, after := range []bool{false, true} {
		for fail := 2; fail <= 4; fail++ {
			t.Run(map[bool]string{false: "opening", true: "closing"}[after]+string(rune('0'+fail)), func(t *testing.T) {
				m, spec, info := hevReleaseFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				guard := func(c context.Context, mutate func() error) error {
					calls++
					if calls == fail && !after {
						cancel()
						return context.Canceled
					}
					if err := mutate(); err != nil {
						return err
					}
					if calls == fail && after {
						cancel()
						return context.Canceled
					}
					return c.Err()
				}
				result, err := m.installHEVImageGuarded(ctx, spec, info, []byte("model verified bytes"), guard)
				if err == nil || result.OK || !errors.Is(err, context.Canceled) {
					t.Fatal("forward admission failure lost", result, err)
				}
				if calls != fail {
					t.Fatal("compensation tried to obtain fresh forward authority", calls, fail)
				}
				hevAssertPair(t, m, nil)
			})
		}
	}
}

func TestHEVGuardedRollbackFailureRemainsFencedAndRetainsBothErrors(t *testing.T) {
	m, spec, info := hevReleaseFixture(t)
	forwardFailure := errors.New("original forward owner expired")
	rollbackFailure := errors.New("modeled original CAS undo failed")
	calls := 0
	rollback := false
	m.updateFault = func(phase string) error {
		if rollback && phase == "hev:before:a_binary" {
			return rollbackFailure
		}
		return nil
	}
	guard := func(_ context.Context, mutate func() error) error {
		calls++
		if err := mutate(); err != nil {
			return err
		}
		if calls == 2 {
			rollback = true
			return forwardFailure
		}
		return nil
	}
	_, err := m.installHEVImageGuarded(context.Background(), spec, info, []byte("model verified bytes"), guard)
	if !errors.Is(err, restorejournal.ErrRecovery) || !errors.Is(err, forwardFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("rollback failure erased an original cause: %v", err)
	}
	if idle := m.hevReleaseIdle(); idle == nil {
		t.Fatal("uncertain undo lost durable recovery fence")
	}
	if _, err := os.Stat(filepath.Join(m.BinDir, spec.Binary)); err != nil {
		t.Fatal("failed undo unexpectedly erased binary", err)
	}
}

func TestHEVGenericApplyCannotBypassOriginalGuard(t *testing.T) {
	m, _, _ := hevReleaseFixture(t)
	if _, err := m.Apply(context.Background(), "hev-socks5-tunnel"); err == nil {
		t.Fatal("generic package Apply bypassed HEV original-owner guard")
	}
	if _, err := os.Stat(m.BinDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unguarded Apply touched executable directory", err)
	}
	if _, err := os.Stat(m.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unguarded Apply initialized journal state", err)
	}
	if _, err := m.ApplyHEVGuarded(context.Background(), nil, nil); err == nil {
		t.Fatal("nil guard admitted")
	}
}

func TestHEVForwardRenameAdmissionIsSeparateFromCompensation(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "late-control-refusal"}[refuse], func(t *testing.T) {
			m, spec, info := hevReleaseFixture(t)
			inside := false
			renames := 0
			late := errors.New("actual rename control expired")
			guard := func(_ context.Context, mutate func() error) error {
				if inside {
					t.Fatal("nested whole CAS guard")
				}
				inside = true
				err := mutate()
				inside = false
				return err
			}
			admitRename := func(_ context.Context, rename func() error) error {
				if !inside {
					t.Fatal("rename escaped original whole CAS observation")
				}
				renames++
				if err := rename(); err != nil {
					return err
				}
				if refuse {
					return late
				}
				return nil
			}
			result, err := m.installHEVImageGuarded(context.Background(), spec, info, []byte("model verified bytes"), guard, admitRename)
			if refuse {
				if result.OK || !errors.Is(err, late) || renames != 1 {
					t.Fatal("rename refusal not preserved or compensation sought new authority", result, err, renames)
				}
				hevAssertPair(t, m, nil)
			} else {
				if err != nil || !result.OK || renames != 3 {
					t.Fatal(result, err, renames)
				}
				hevAssertPair(t, m, []byte("model verified bytes"))
			}
		})
	}
}
