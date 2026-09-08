package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestImportDraftGuardedRollback(t *testing.T) {
	for _, change := range []string{"none", "service", "apply", "safe-mode", "write-failure"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			s, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.UpdateService("youtube", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
				t.Fatal(err)
			}
			before := s.Get()
			beforeFile, _ := os.ReadFile(path)
			undo, err := s.ReplaceDraftWithRollback(map[string]ServiceState{"telegram": {Enabled: true, Route: "usque"}})
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "service":
				err = s.UpdateService("youtube", ServiceState{Route: "direct"})
			case "apply":
				err = s.ApplyDraft()
			case "safe-mode":
				err = s.SetSafeMode(false)
			case "write-failure":
				s.path = filepath.Join(path, "cannot-write.json")
			}
			if err != nil {
				t.Fatal(err)
			}
			current := s.Get()
			currentFile, _ := os.ReadFile(path)
			err = undo()
			if change != "none" {
				if err == nil || !reflect.DeepEqual(current, s.Get()) {
					t.Fatal("undo clobbered changed config or failed to retain memory on I/O error")
				}
				afterFile, _ := os.ReadFile(path)
				if !bytes.Equal(currentFile, afterFile) {
					t.Fatal("undo clobbered disk")
				}
				if change != "write-failure" {
					return
				}
				s.path = path
				if err = undo(); err != nil {
					t.Fatalf("undo not retryable: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, s.Get()) {
				t.Fatal("config snapshot/revisions not restored")
			}
			afterFile, _ := os.ReadFile(path)
			if !bytes.Equal(beforeFile, afterFile) {
				t.Fatal("config disk snapshot not restored")
			}
			if err := undo(); err != nil {
				t.Fatal("undo not idempotent")
			}
		})
	}
}
