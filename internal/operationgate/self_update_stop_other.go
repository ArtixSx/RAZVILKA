//go:build !linux && !windows

package operationgate

import (
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var errControlLockBusy = errors.New("control authority lock unavailable")

func controlPrivate(os.FileInfo) bool { return false }
func controlFileFlags() int           { return 0 }
func controlFileLock(*os.File) error  { return ErrSelfUpdateStopJournal }
func controlSync(*ownedfs.Root) error { return ErrSelfUpdateStopJournal }
