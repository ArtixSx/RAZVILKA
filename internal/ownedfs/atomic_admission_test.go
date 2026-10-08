package ownedfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func stagedName(t *testing.T, path string) string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".transaction-") {
			if name != "" {
				t.Fatal("multiple staged files")
			}
			name = entry.Name()
		}
	}
	if name == "" {
		t.Fatal("missing staged file")
	}
	return filepath.Join(path, name)
}

func TestAtomicAdmissionRejectsChangedTemporaryWithoutRemovingForeignFile(t *testing.T) {
	for _, change := range []string{"payload", "replacement", "symlink", "mode"} {
		t.Run(change, func(t *testing.T) {
			if change == "mode" && runtime.GOOS == "windows" {
				t.Skip("Windows backend has no Unix private mode")
			}
			path := t.TempDir()
			r, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err := r.WriteAtomic("state", []byte("before"), 0o600); err != nil {
				t.Fatal(err)
			}
			var temporary string
			admissions := 0
			attempted, err := r.WriteAtomicWithRenameAdmission("state", []byte("after"), 0o600, func(rename func() error) error {
				admissions++
				return rename()
			}, func() error {
				temporary = stagedName(t, path)
				switch change {
				case "payload":
					return os.WriteFile(temporary, []byte("other"), 0o600)
				case "replacement", "symlink":
					if err := os.Rename(temporary, filepath.Join(path, "original-stage")); err != nil {
						return err
					}
					if change == "replacement" {
						return os.WriteFile(temporary, []byte("after"), 0o600)
					}
					if err := os.Symlink(filepath.Join(path, "original-stage"), temporary); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				case "mode":
					return os.Chmod(temporary, 0o644)
				}
				return nil
			})
			if attempted || admissions != 0 || !errors.Is(err, ErrStagedFileChanged) {
				t.Fatalf("changed stage reached rename: %v %d %v", attempted, admissions, err)
			}
			data, err := os.ReadFile(filepath.Join(path, "state"))
			if err != nil || string(data) != "before" {
				t.Fatal("changed stage overwrote before-image")
			}
			_, statErr := os.Lstat(temporary)
			if change == "replacement" || change == "symlink" {
				if statErr != nil {
					t.Fatal("cleanup removed a foreign temporary inode")
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("owned refused stage was not cleaned")
			}
		})
	}
}

func TestAtomicAdmissionSealsSkippedRepeatedSwallowedAndLateRename(t *testing.T) {
	for _, behavior := range []string{"skip", "repeat", "swallow", "late", "panic"} {
		t.Run(behavior, func(t *testing.T) {
			path := t.TempDir()
			r, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var retained func() error
			var attempted bool
			var syscallCause error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				attempted, err = r.WriteAtomicWithRenameAdmission("state", []byte("after"), 0o600, func(rename func() error) error {
					retained = rename
					switch behavior {
					case "repeat":
						if err := rename(); err != nil {
							return err
						}
						_ = rename() // A swallowed duplicate still refuses success.
					case "swallow":
						if err := os.Mkdir(filepath.Join(path, "state"), 0o700); err != nil {
							return err
						}
						syscallCause = rename()
					case "panic":
						panic("admission panic")
					}
					return nil
				}, nil)
			}()
			if behavior == "panic" {
				if !panicked {
					t.Fatal("admission panic disappeared")
				}
			} else if behavior == "swallow" {
				if !attempted || syscallCause == nil || !errors.Is(err, syscallCause) {
					t.Fatal("swallowed syscall failure became success")
				}
			} else if !errors.Is(err, ErrRenameAdmission) || attempted != (behavior == "repeat") {
				t.Fatalf("bad admission became success: %v %v", attempted, err)
			}
			if retained == nil || !errors.Is(retained(), ErrRenameAdmission) {
				t.Fatal("retained callback was not sealed")
			}
			entries, _ := os.ReadDir(path)
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".transaction-") {
					t.Fatal("admission left its owned stage")
				}
			}
			if behavior != "repeat" && behavior != "swallow" {
				if _, err := os.Stat(filepath.Join(path, "state")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("late or skipped callback wrote state")
				}
			}
		})
	}
}
