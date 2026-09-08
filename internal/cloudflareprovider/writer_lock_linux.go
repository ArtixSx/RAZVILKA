//go:build linux

package cloudflareprovider

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openWriterFile(root *ownedfs.Root, create bool) (*os.File, error) {
	flags := os.O_RDWR | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(writerLockFile, flags, 0o600)
}

func lockWriterFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockWriterFile(file *os.File) { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }
