package engineconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStageRollbackFailuresAreNotHidden(t *testing.T) {
	for _, mode := range []string{"restore-existing", "remove-new", "mkdir-failure", "rollback-write-failure", "rollback-remove-failure"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
			first := m.stagePath("nfqws2", "user-list")
			existed := mode == "restore-existing" || mode == "rollback-write-failure"
			if existed {
				if _, err := m.Stage("nfqws2", "user-list", "before.example\n"); err != nil {
					t.Fatal(err)
				}
			}
			writes, removes, mkdirs := 0, 0, 0
			io := draftFileIO{
				write: func(path string, data []byte, modeBits os.FileMode) error {
					writes++
					if writes == 2 || mode == "rollback-write-failure" && writes == 3 {
						return errors.New("synthetic private write failure")
					}
					return writeAtomic(path, data, modeBits)
				},
				remove: func(path string) error {
					removes++
					if mode == "rollback-remove-failure" {
						return errors.New("synthetic remove failure")
					}
					return os.Remove(path)
				},
				mkdir: func(path string, modeBits os.FileMode) error {
					mkdirs++
					if mode == "mkdir-failure" && mkdirs == 2 {
						return errors.New("synthetic mkdir failure")
					}
					return os.MkdirAll(path, modeBits)
				},
			}
			_, err := m.stageValidatedWithIO([]StageItem{{EngineID: "nfqws2", FileID: "user-list", Content: "new.example\n"}, {EngineID: "nfqws2", FileID: "exclude-list", Content: "second.example\n"}}, ValidatePrivateContent, io)
			if err == nil {
				t.Fatal("injected write failure ignored")
			}
			incomplete := mode == "rollback-write-failure" || mode == "rollback-remove-failure"
			if errors.Is(err, ErrStageRollback) != incomplete {
				t.Fatalf("incorrect rollback classification: %v", err)
			}
			data, readErr := os.ReadFile(first)
			switch {
			case incomplete:
				if readErr != nil || string(data) != "new.example\n" {
					t.Fatal("unexpected incomplete state")
				}
			case existed:
				if readErr != nil || string(data) != "before.example\n" {
					t.Fatal("old draft not restored")
				}
			default:
				if !errors.Is(readErr, os.ErrNotExist) || removes != 1 {
					t.Fatal("new draft not removed")
				}
			}
		})
	}
}
