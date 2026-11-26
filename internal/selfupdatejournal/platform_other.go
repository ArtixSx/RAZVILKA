//go:build !linux && !windows

package selfupdatejournal

import (
	"errors"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
)

func lockFile(_ *os.File) error { return errors.New("self update journal locking unavailable") }
func fileFlags() int            { return 0 }
func syncJournal(_ *ownedfs.Root) error {
	return errors.New("self update journal durability unavailable")
}
