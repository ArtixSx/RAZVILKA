//go:build linux

package ownedfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLstatChildOnlyReportsActualAbsentBasename(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, name := range []string{"", ".", "..", "../outside", "nested/child", dir} {
		if _, err := r.LstatChild(name); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid name was accepted or mistaken for absence", name, err)
		}
	}
	if _, err := r.LstatChild("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("real missing child was not reported", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "present"), 0700); err != nil {
		t.Fatal(err)
	}
	if info, err := r.LstatChild("present"); err != nil || !info.IsDir() {
		t.Fatal("real child directory was not observed", err)
	}
	for _, target := range []string{"missing", "present"} {
		if err := os.Symlink(target, filepath.Join(dir, "link-"+target)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.LstatChild("link-" + target); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatal("symlink was accepted or mistaken for absence", target, err)
		}
	}
}

func TestLstatChildReplacementNeverTurnsDanglingLinkIntoAbsence(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	child := filepath.Join(dir, "child")
	if err := os.WriteFile(child, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	// The basename always exists. Atomic rename alternates a regular object
	// and a dangling symlink while the held root is inspected concurrently.
	done := make(chan error, 1)
	go func() {
		staged := filepath.Join(dir, "replacement")
		for i := 0; i < 256; i++ {
			if i%2 == 0 {
				err = os.Symlink("absent-target", staged)
			} else {
				err = os.WriteFile(staged, []byte("replacement"), 0600)
			}
			if err != nil {
				done <- err
				return
			}
			if err := os.Rename(staged, child); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	var observed error
	for i := 0; i < 1024; i++ {
		if _, err := r.LstatChild("child"); errors.Is(err, os.ErrNotExist) {
			observed = err
			break
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if observed != nil {
		t.Fatal("existing basename was mistaken for absence", observed)
	}
}
