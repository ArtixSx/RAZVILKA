//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Filesystem-only native test: no executable, Lua, process or network grant.
func TestNativeManagedNFQWSSealsBeforeRenameAdmission(t *testing.T) {
	for _, outcome := range []string{"publish", "decline", "sealed-crash"} {
		t.Run(outcome, func(t *testing.T) {
			root := t.TempDir()
			stage := filepath.Join(root, "stage")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			decline := errors.New("known decline")
			entered := false
			err := publishManagedNFQWS(context.Background(), root, "stage", "generation", func(rename func() error) error {
				entered = true
				info, err := os.Stat(stage)
				if err != nil || info.Mode().Perm() != 0555 {
					t.Fatal("stage was not sealed before short admission", info, err)
				}
				if outcome == "decline" {
					return decline
				}
				return rename()
			}, func(point string) error {
				if outcome == "sealed-crash" && point == "after:bundle-stage-chmod" {
					return decline
				}
				return nil
			})
			if outcome == "publish" {
				info, statErr := os.Stat(filepath.Join(root, "generation"))
				if err != nil || !entered || statErr != nil || info.Mode().Perm() != 0555 {
					t.Fatal("actual rename failed", err, statErr)
				}
				return
			}
			if !errors.Is(err, decline) || entered != (outcome == "decline") {
				t.Fatal("wrong admission/crash cut", entered, err)
			}
			mode := os.FileMode(0700)
			if outcome == "sealed-crash" {
				mode = 0555
			}
			info, statErr := os.Stat(stage)
			if statErr != nil || info.Mode().Perm() != mode {
				t.Fatal("unpublished stage retirement/recovery mode changed", info, statErr)
			}
			if _, err := os.Stat(filepath.Join(root, "generation")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("decline/crash published a generation", err)
			}
		})
	}
}
