//go:build !linux && !windows

package components

import (
	"errors"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
)

func lockUpdateFile(_ *os.File) error { return errors.New("component journal locking unavailable") }
func updateFileFlags() int            { return 0 }
func syncUpdateDirectory(_ *ownedfs.Root) error {
	return errors.New("component journal durability unavailable")
}
