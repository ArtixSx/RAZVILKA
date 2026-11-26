package restorejournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutableFileTargetRetainsCASAndStateDefaultMode(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "owned-binary")
	target, err := OpenExecutableFileTarget(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	before, err := target.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after := Image{Exists: true, Data: []byte("owned executable bytes")}
	if err = target.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		info, err := os.Stat(binary)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatal("executable mode lost", err)
		}
	}
	if err = target.CompareAndSwap(context.Background(), before, Image{Exists: true, Data: []byte("stale write")}); err != ErrConflict {
		t.Fatal("executable bypassed image CAS", err)
	}
	statePath := filepath.Join(root, "private-state")
	state, err := OpenFileTarget(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err = state.CompareAndSwap(context.Background(), Image{}, after); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		info, err := os.Stat(statePath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("state default became executable", err)
		}
	}
}

func TestExecutableFileTargetRenameAdmissionKeepsTypedModeAndCAS(t *testing.T) {
	for _, executable := range []bool{false, true} {
		t.Run(map[bool]string{false: "private-state", true: "executable"}[executable], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "target")
			var target *FileTarget
			var err error
			if executable {
				target, err = OpenExecutableFileTarget(path)
			} else {
				target, err = OpenFileTarget(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			calls := 0
			after := Image{Exists: true, Data: []byte("exact installed bytes")}
			if err := target.CompareAndSwapWithRenameAdmission(context.Background(), Image{}, after, func(_ context.Context, rename func() error) error { calls++; return rename() }); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal("rename admission not exact once", calls)
			}
			if runtime.GOOS == "linux" {
				mode := os.FileMode(0600)
				if executable {
					mode = 0755
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatal("typed publication mode lost", info, err)
				}
			}
			if err := target.CompareAndSwapWithRenameAdmission(context.Background(), Image{}, after, func(context.Context, func() error) error { t.Fatal("stale image reached rename admission"); return nil }); !errors.Is(err, ErrConflict) {
				t.Fatal("stale executable bypassed CAS", err)
			}
		})
	}
}

func TestExecutableRenameAdmissionRefusalAndChangedPriorMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary")
	target, err := OpenExecutableFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	refused := errors.New("original control admission refused")
	if err := target.CompareAndSwapWithRenameAdmission(context.Background(), Image{}, Image{Exists: true, Data: []byte("new")}, func(context.Context, func() error) error { return refused }); !errors.Is(err, ErrAborted) || !errors.Is(err, refused) {
		t.Fatal("clean rename refusal lost", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused rename published bytes", err)
	}
	if runtime.GOOS != "linux" {
		return
	}
	before := Image{Exists: true, Data: []byte("prior")}
	if err := target.CompareAndSwap(context.Background(), Image{}, before); err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwapWithRenameAdmission(context.Background(), before, Image{Exists: true, Data: []byte("changed")}, func(context.Context, func() error) error { t.Fatal("changed prior mode reached rename"); return nil }, func() error { return os.Chmod(path, 0700) }); err == nil {
		t.Fatal("prior mode change adopted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "prior" {
		t.Fatal("mode conflict changed original bytes", err)
	}
}
func TestExecutableFileTargetRejectsUnknownPriorMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix executable mode contract")
	}
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("prior"), 0700); err != nil {
		t.Fatal(err)
	}
	target, err := OpenExecutableFileTarget(path)
	if target != nil {
		target.Close()
	}
	if err == nil {
		t.Fatal("rollback could silently change unknown original mode")
	}
}
