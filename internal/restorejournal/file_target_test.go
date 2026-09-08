package restorejournal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileTargetReadOnlyAndExactCAS(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	image, err := ReadFileImage(ctx, path)
	if err != nil || image.Exists {
		t.Fatal("missing read failed")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("read-only access created files")
	}
	f, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if other, err := OpenFileTarget(path); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second lease admitted")
	}
	if err := f.CompareAndSwap(ctx, Image{}, content("")); err != nil {
		t.Fatal(err)
	}
	if err := f.CompareAndSwap(ctx, Image{}, content("wrong")); !errors.Is(err, ErrConflict) {
		t.Fatal("empty confused with absent")
	}
	after := content("real state")
	if err := f.CompareAndSwap(ctx, content(""), after); err != nil {
		t.Fatal(err)
	}
	after.Data[0] = '!'
	got, err := f.Read(ctx)
	if err != nil || !equal(got, content("real state")) {
		t.Fatal("caller aliases persisted state")
	}
	got.Data[0] = '!'
	if err := f.CompareAndSwap(ctx, content("real state"), Image{}); err != nil {
		t.Fatal(err)
	}
	if err := f.CompareAndSwap(ctx, Image{}, Image{}); err != nil {
		t.Fatal("absent no-op failed")
	}
	if !validHash(f.Binding()) || strings.Contains(fmt.Sprintf("%v %#v", f, f), path) {
		t.Fatal("private binding/format")
	}
	binding := f.Binding()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("read after close")
	}
	if err := f.CompareAndSwap(ctx, Image{}, content("x")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("write after close")
	}
	f, err = OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if binding != f.Binding() {
		t.Fatal("binding unstable after restart")
	}
}

func TestFileTargetWriteFailureIsAmbiguous(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			f, err := OpenFileTarget(filepath.Join(t.TempDir(), "data"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.CompareAndSwap(context.Background(), Image{}, content("before")); err != nil {
				t.Fatal(err)
			}
			write := f.write
			f.write = func(after Image) error {
				if commit {
					if err := write(after); err != nil {
						return err
					}
				}
				return injected
			}
			if err := f.CompareAndSwap(context.Background(), content("before"), content("after")); !errors.Is(err, ErrRecovery) || strings.Contains(fmt.Sprint(err), injected.Error()) {
				t.Fatal("write failure not safely classified")
			}
			got, err := f.Read(context.Background())
			want := content("before")
			if commit {
				want = content("after")
			}
			if err != nil || !equal(got, want) {
				t.Fatal("wrong actual state after error")
			}
		})
	}
}

func TestFileTargetRejectsUnsafeInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	names := []string{journalFile, leaseFile, ".state-other.lock"}
	if runtime.GOOS == "windows" {
		names = append(names, "AUX", "NUL.txt", "COM1", "config.json.", "config.json ")
	}
	for _, name := range names {
		if f, err := OpenFileTarget(filepath.Join(dir, name)); err == nil {
			f.Close()
			t.Fatalf("reserved file accepted: %q", name)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("invalid paths created files")
	}
	path := filepath.Join(dir, "target")
	f, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.CompareAndSwap(ctx, Image{}, content("no")); err == nil {
		t.Fatal("cancelled write")
	}
	if err := f.CompareAndSwap(context.Background(), Image{}, Image{Exists: false, Data: []byte("no")}); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid absent image")
	}
	if err := f.CompareAndSwap(context.Background(), Image{}, content(strings.Repeat("x", MaxImageBytes+1))); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized write")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), MaxImageBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(context.Background()); err == nil {
		t.Fatal("oversized read")
	}
}
