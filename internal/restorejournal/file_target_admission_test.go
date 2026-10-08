package restorejournal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func publicationFixture(t *testing.T) (*FileTarget, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state")
	f, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.CompareAndSwap(context.Background(), Image{}, content("before")); err != nil {
		t.Fatal(err)
	}
	return f, path
}

func assertPublicationImage(t *testing.T, f *FileTarget, want string) {
	t.Helper()
	got, err := f.Read(context.Background())
	if err != nil || !equal(got, content(want)) {
		t.Fatalf("wrong exact image: %v", err)
	}
}

func assertNoPublicationStage(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".transaction-") {
			t.Fatal("owned stage remained after publication")
		}
	}
}

func TestFileTargetStagedPublicationKeepsOriginalContextLeaseAndBoundaries(t *testing.T) {
	f, path := publicationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	after := content("after")
	prepared, admitted, inside, synced := false, false, false, false
	f.syncDir = func() error {
		if inside || !admitted {
			t.Fatal("directory sync occurred inside/before admission")
		}
		synced = true
		return nil
	}
	err := f.CompareAndSwapWithRenameAdmission(ctx, content("before"), after, func(actual context.Context, rename func() error) error {
		if actual != ctx || !prepared {
			t.Fatal("admission changed context or ran before staging")
		}
		inside = true
		err := rename()
		inside = false
		admitted = true
		return err
	}, func() error {
		prepared = true
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "before" {
			t.Fatal("staging published the after-image")
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		stages := 0
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".transaction-") {
				stages++
				data, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
				if err != nil || string(data) != "after" {
					t.Fatal("prepared hook preceded complete stage")
				}
			}
		}
		if stages != 1 {
			t.Fatal("prepared hook did not own exactly one stage")
		}
		if other, err := OpenFileTarget(path); !errors.Is(err, ErrBusy) {
			if other != nil {
				_ = other.Close()
			}
			t.Fatal("staging released the original writer lease")
		}
		after.Data[0] = '!' // Caller's mutable image cannot change the staged copy.
		return nil
	})
	if err != nil || !prepared || !admitted || !synced {
		t.Fatalf("staged publication failed: %v", err)
	}
	assertPublicationImage(t, f, "after")
	assertNoPublicationStage(t, path)
}

func TestFileTargetStagedPublicationRechecksBytesAndInodeAfterPrepared(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprint(replacement), func(t *testing.T) {
			f, path := publicationFixture(t)
			admitted := false
			err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("before"), content("after"), func(_ context.Context, rename func() error) error {
				admitted = true
				return rename()
			}, func() error {
				if replacement {
					if err := os.Rename(path, path+"-original"); err != nil {
						return err
					}
					return os.WriteFile(path, []byte("before"), 0o600)
				}
				return os.WriteFile(path, []byte("third"), 0o600)
			})
			if !errors.Is(err, ErrConflict) || admitted {
				t.Fatalf("prepared conflict reached admission: %v", err)
			}
			want := "third"
			if replacement {
				want = "before"
			}
			assertPublicationImage(t, f, want)
			assertNoPublicationStage(t, path)
		})
	}
}

func TestFileTargetStagedPublicationRefusalCancellationAndInvalidInput(t *testing.T) {
	f, path := publicationFixture(t)
	admit := func(_ context.Context, rename func() error) error { return rename() }
	for _, after := range []Image{{}, {Data: []byte("invalid")}, content(strings.Repeat("x", MaxImageBytes+1))} {
		if err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("before"), after, admit); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid rename-only image admitted")
		}
	}
	if err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("stale"), content("after"), admit); !errors.Is(err, ErrConflict) {
		t.Fatal("stale before-image admitted")
	}
	if err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("before"), content("after"), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil admission accepted")
	}
	if err := f.CompareAndSwapWithRenameAdmission(nil, content("before"), content("after"), admit); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context accepted")
	}
	if err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("before"), content("after"), admit, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("multiple prepared hooks accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := f.CompareAndSwapWithRenameAdmission(ctx, content("before"), content("after"), func(_ context.Context, _ func() error) error {
		t.Fatal("canceled stage reached admission")
		return nil
	}, func() error { cancel(); return nil })
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("canceled prepared image accepted: %v", err)
	}
	cause := errors.New("private admission path: " + path)
	err = f.CompareAndSwapWithRenameAdmission(context.Background(), content("before"), content("after"), func(_ context.Context, _ func() error) error { return cause })
	if !errors.Is(err, cause) || !errors.Is(err, ErrRecovery) || strings.Contains(fmt.Sprintf("%v %#v", err, err), path) {
		t.Fatal("refusal lost its cause or exposed its private path")
	}
	assertPublicationImage(t, f, "before")
	assertNoPublicationStage(t, path)
}

func TestFileTargetStagedPublicationSerializesCloseThroughOriginalOwner(t *testing.T) {
	f, path := publicationFixture(t)
	entered, release, closing := make(chan struct{}), make(chan struct{}), make(chan struct{})
	closed := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- f.CompareAndSwapWithRenameAdmission(context.Background(), content("before"), content("after"), func(_ context.Context, rename func() error) error { return rename() }, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	select {
	case <-entered:
	case <-watchdog.C:
		t.Fatal("publication never reached staged boundary")
	}
	go func() {
		close(closing)
		closed <- f.Close()
	}()
	<-closing
	select {
	case <-closed:
		t.Fatal("Close released the original owner during staging")
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-watchdog.C:
		t.Fatal("publication did not finish")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-watchdog.C:
		t.Fatal("Close did not join publication")
	}
	if _, err := f.Read(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed original target remained live")
	}
	reopened, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertPublicationImage(t, reopened, "after")
	assertNoPublicationStage(t, path)
}

func TestFileTargetStagedPublicationUnknownStillAllowsOnlyExactSameTargetRepair(t *testing.T) {
	for _, failure := range []string{"admission-close", "directory-sync", "readback-cancel", "readback-third"} {
		t.Run(failure, func(t *testing.T) {
			f, path := publicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("private publication failure: " + path)
			syncDir := f.syncDir
			if failure == "directory-sync" {
				f.syncDir = func() error { return cause }
			} else if failure == "readback-third" {
				f.syncDir = func() error { return os.WriteFile(path, []byte("third"), 0o600) }
			}
			err := f.CompareAndSwapWithRenameAdmission(ctx, content("before"), content("after"), func(_ context.Context, rename func() error) error {
				if err := rename(); err != nil {
					return err
				}
				if failure == "admission-close" {
					return cause
				}
				if failure == "readback-cancel" {
					cancel()
				}
				return nil
			})
			if !errors.Is(err, ErrRecovery) || strings.Contains(err.Error(), path) {
				t.Fatalf("uncertain publication became confirmed: %v", err)
			}
			if (failure == "admission-close" || failure == "directory-sync") && !errors.Is(err, cause) {
				t.Fatal("uncertain publication lost the actual cause")
			}
			f.syncDir = syncDir
			if failure == "readback-third" {
				if err := f.CompareAndSwap(context.Background(), content("after"), content("unknown")); !errors.Is(err, ErrConflict) {
					t.Fatal("repair overwrote an independent third image")
				}
				assertPublicationImage(t, f, "third")
			} else {
				assertPublicationImage(t, f, "after")
				if err := f.CompareAndSwap(context.Background(), content("after"), content("unknown")); err != nil {
					t.Fatalf("same target could not repair its exact proposed image: %v", err)
				}
				assertPublicationImage(t, f, "unknown")
			}
			assertNoPublicationStage(t, path)
		})
	}
}
