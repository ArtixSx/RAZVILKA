//go:build linux

package restorejournal

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestArtifactExpectedReadComparisonActualFDsAndRevocation(t *testing.T) {
	target, image, pool, _ := artifactComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := os.Open(pool)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var late *ArtifactSourceComparison
	var lateCtx context.Context
	var poolFD, managedFD *os.File
	callbackErr := errors.New("expected reader callback error")
	err = target.WithExpectedReadComparison(ctx, image, func(c context.Context, got Image, proof *ArtifactSourceComparison) error {
		late, lateCtx, poolFD, managedFD = proof, c, proof.hashed, proof.managedHeld
		if !equal(got, image) || proof.MatchHeld(c, held) != nil || managedFD == nil || poolFD == nil {
			t.Fatal("actual original hash descriptors not retained")
		}
		if proof.MatchHeld(c, managedFD) == nil {
			t.Fatal("same bytes different inode accepted as pool descriptor")
		}
		copyProof := &ArtifactSourceComparison{self: proof}
		if copyProof.MatchHeld(c, held) == nil || proof.MatchHeld(ctx, held) == nil {
			t.Fatal("copied/foreign proof accepted")
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatal(err)
	}
	if late.MatchHeld(lateCtx, held) == nil {
		t.Fatal("late proof escaped")
	}
	for _, file := range []*os.File{poolFD, managedFD} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("actual hash descriptor escaped", err)
		}
	}
}

func TestArtifactExpectedReadComparisonAlwaysJoinsBothReaders(t *testing.T) {
	for _, kind := range []string{"error", "panic", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			target, image, _, _ := artifactComparisonFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cut := errors.New("one original hash worker cut")
			var managedJoined atomic.Bool
			var invoked bool
			var caught any
			fault := func(role, step string) error {
				if role == "managed" && step == "hashed" {
					managedJoined.Store(true)
				}
				if role == "pool" && step == "opened" {
					switch kind {
					case "error":
						return cut
					case "panic":
						panic(cut)
					case "cancel":
						cancel()
					}
				}
				return nil
			}
			var err error
			func() {
				defer func() { caught = recover() }()
				err = target.withExpectedReadComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
			}()
			if invoked {
				t.Fatal("failed worker invoked callback")
			}
			if kind == "panic" && caught != cut {
				t.Fatal("original worker panic changed", caught)
			}
			if kind == "error" && !errors.Is(err, cut) {
				t.Fatal("worker error lost", err)
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if kind != "cancel" && !managedJoined.Load() {
				t.Fatal("returned/panicked before other full reader joined")
			}
		})
	}
}

func TestArtifactExpectedReadComparisonMutationBetweenReadersRefuses(t *testing.T) {
	for _, role := range []string{"managed", "pool"} {
		t.Run(role, func(t *testing.T) {
			target, image, pool, managed := artifactComparisonFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var changed atomic.Bool
			fault := func(current, step string) error {
				if current != role || step != "hashed" || !changed.CompareAndSwap(false, true) {
					return nil
				}
				path := managed
				if role == "pool" {
					path = pool
				}
				// Actual equal-size in-place write; ctime/byte/FD bookends must
				// reject even when the other hash has already completed.
				info, err := os.Stat(path)
				if err != nil {
					return err
				}
				if err := os.Chmod(path, info.Mode().Perm()|0200); err != nil {
					return err
				}
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				_, writeErr := file.WriteAt([]byte{0}, 0)
				return errors.Join(writeErr, file.Close())
			}
			invoked := false
			err := target.withExpectedReadComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
			if !changed.Load() || invoked || !errors.Is(err, ErrConflict) {
				t.Fatal("mutation during actual reads accepted", changed.Load(), invoked, err)
			}
		})
	}
}

func TestArtifactExpectedReadComparisonFreshReopenRejectsEqualByteReplacement(t *testing.T) {
	target, image, pool, _ := artifactComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := os.ReadFile(pool)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	fault := func(role, step string) error {
		if role != "joined" || step != "before-reopen" {
			return nil
		}
		changed = true
		if err := os.Rename(pool, pool+".previous"); err != nil {
			return err
		}
		return os.WriteFile(pool, data, 0555)
	}
	invoked := false
	err = target.withExpectedReadComparison(ctx, image, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil }, fault)
	if !changed || invoked || !errors.Is(err, ErrConflict) {
		t.Fatal("same-byte foreign pool inode accepted", changed, invoked, err)
	}
}

func TestArtifactExpectedReadComparisonExpectedImageNeverSubstitutesForManagedBytes(t *testing.T) {
	target, _, _, _ := artifactComparisonFixture(t)
	other := artifactFixtureImage(t, target.artifactPath, []byte("another actual owned pool member"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	invoked := false
	err := target.WithExpectedReadComparison(ctx, other, func(context.Context, Image, *ArtifactSourceComparison) error { invoked = true; return nil })
	if invoked || !errors.Is(err, ErrConflict) {
		t.Fatal("expected pin replaced actual managed hash", invoked, err)
	}
}
