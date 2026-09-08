//go:build !linux && !windows

package restorejournal

// Unsupported platforms cannot participate in state-file recovery.

import (
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
)

func openPrivate(_ *ownedfs.Root, _ string, _ bool) (*os.File, error) { return nil, ErrUnavailable }
func openReadOnly(_ *ownedfs.Root, _ string) (*os.File, error)        { return nil, ErrUnavailable }
func lockFile(_ *os.File) error                                       { return ErrUnavailable }
func syncJournalDir(_ *ownedfs.Root) error                            { return ErrUnavailable }
