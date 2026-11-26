//go:build linux

package restorejournal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func artifactComparisonFixture(t *testing.T) (*ArtifactFileTarget, Image, string, string) {
	t.Helper()
	base := t.TempDir()
	artifacts := filepath.Join(base, "artifacts")
	bin := filepath.Join(base, "bin")
	for _, dir := range []string{artifacts, bin} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	image := artifactFixtureImage(t, artifacts, bytes.Repeat([]byte("actual artifact comparison fixture\n"), 32768))
	ref, _ := artifactImageReference(image)
	path := filepath.Join(bin, "mihomo")
	target, err := OpenArtifactExecutableTarget(path, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := target.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := target.CompareAndSwap(context.Background(), Image{}, image); err != nil {
		t.Fatal(err)
	}
	return target, image, filepath.Join(artifacts, ref.SHA256+".bin"), path
}

func TestArtifactComparisonActualSameFileAndRevokedScopes(t *testing.T) {
	target, image, pool, _ := artifactComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := os.Open(pool)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	fd, err := unix.FcntlInt(held.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	alias := os.NewFile(uintptr(fd), "[actual duplicate]")
	defer alias.Close()
	callbackErr := errors.New("comparison callback cause")
	var late *ArtifactSourceComparison
	var lateCtx context.Context
	var actualHashFD *os.File
	err = target.WithReadComparison(ctx, func(c context.Context, actual Image, proof *ArtifactSourceComparison) error {
		late, lateCtx, actualHashFD = proof, c, proof.hashed
		if !equal(actual, image) || proof.MatchHeld(c, held) != nil || proof.MatchHeld(c, alias) != nil {
			t.Error("actual hashed inode duplicate refused")
		}
		if proof.MatchHeld(ctx, held) == nil {
			t.Error("foreign context admitted")
		}
		copy := &ArtifactSourceComparison{self: proof, target: proof.target, ctx: c, open: true, hashed: proof.hashed, poolName: proof.poolName, pool: proof.pool, managed: proof.managed}
		if copy.MatchHeld(c, held) == nil {
			t.Error("copied comparison admitted")
		}
		canceled, done := context.WithCancel(c)
		done()
		if !errors.Is(proof.MatchHeld(canceled, held), context.Canceled) {
			t.Error("cancellation cause lost")
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatal("callback error lost", err)
	}
	if late.MatchHeld(lateCtx, held) == nil {
		t.Fatal("expired comparison reused")
	}
	if _, err := actualHashFD.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("actual hashed FD not closed", err)
	}
	func() {
		defer func() {
			if recover() != callbackErr {
				t.Error("panic changed")
			}
		}()
		_ = target.WithReadComparison(ctx, func(c context.Context, _ Image, proof *ArtifactSourceComparison) error {
			late, lateCtx, actualHashFD = proof, c, proof.hashed
			panic(callbackErr)
		})
	}()
	if late.MatchHeld(lateCtx, held) == nil {
		t.Fatal("panic left comparison open")
	}
	if _, err := actualHashFD.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("panic leaked actual hash FD", err)
	}
}

func TestArtifactComparisonRejectsActualForeignAndChangedFiles(t *testing.T) {
	for _, scenario := range []string{"different-inode", "replaced-held-fd", "pool-replaced", "managed-replaced", "hardlink-alias", "restored-mode-ctime"} {
		t.Run(scenario, func(t *testing.T) {
			target, _, pool, managed := artifactComparisonFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			held, err := os.Open(pool)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			data, err := os.ReadFile(pool)
			if err != nil {
				t.Fatal(err)
			}
			foreignPath := filepath.Join(t.TempDir(), "same-bytes")
			if err := os.WriteFile(foreignPath, data, 0555); err != nil {
				t.Fatal(err)
			}
			foreign, err := os.Open(foreignPath)
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			callbackErr := errors.New("actual source changed callback")
			var restore func() error
			err = target.WithReadComparison(ctx, func(c context.Context, _ Image, proof *ArtifactSourceComparison) error {
				switch scenario {
				case "different-inode":
					if proof.MatchHeld(c, foreign) == nil {
						t.Error("same-byte foreign inode matched")
					}
					return callbackErr
				case "replaced-held-fd":
					backup, err := unix.FcntlInt(held.Fd(), unix.F_DUPFD_CLOEXEC, 0)
					if err != nil {
						return err
					}
					restore = func() error {
						err := unix.Dup3(backup, int(held.Fd()), unix.O_CLOEXEC)
						return errors.Join(err, unix.Close(backup))
					}
					if err := unix.Dup3(int(foreign.Fd()), int(held.Fd()), unix.O_CLOEXEC); err != nil {
						return err
					}
					if proof.MatchHeld(c, held) == nil {
						t.Error("replaced actual descriptor matched")
					}
					return callbackErr
				case "pool-replaced", "managed-replaced":
					path, mode := pool, os.FileMode(0555)
					if scenario == "managed-replaced" {
						path, mode = managed, 0755
					}
					if err := os.Rename(path, path+".original"); err != nil {
						return err
					}
					restore = func() error { return errors.Join(os.Remove(path), os.Rename(path+".original", path)) }
					if err := os.WriteFile(path, data, mode); err != nil {
						return err
					}
				case "hardlink-alias":
					alias := pool + ".alias"
					if err := os.Link(pool, alias); err != nil {
						return err
					}
					restore = func() error { return os.Remove(alias) }
				case "restored-mode-ctime":
					before := proof.pool
					changed := false
					for range 4096 {
						if err := held.Chmod(0755); err != nil {
							return err
						}
						if err := held.Chmod(0555); err != nil {
							return err
						}
						actual, err := held.Stat()
						if err != nil {
							return err
						}
						id, err := artifactReadFingerprint(actual)
						if err != nil {
							return err
						}
						if id.ctimeSeconds != before.ctimeSeconds || id.ctimeNanos != before.ctimeNanos {
							changed = true
							break
						}
					}
					if !changed {
						t.Error("actual kernel CTIM did not advance")
					}
				}
				if proof.MatchHeld(c, held) == nil {
					t.Error("changed original source matched")
				}
				return callbackErr
			})
			if restore != nil {
				if err := restore(); err != nil {
					t.Fatal("restore fixture", err)
				}
			}
			if !errors.Is(err, callbackErr) {
				t.Fatal("callback cause lost", err)
			}
			if scenario != "different-inode" && scenario != "replaced-held-fd" && !errors.Is(err, ErrConflict) {
				t.Fatal("closing source change lost", err)
			}
		})
	}
}
