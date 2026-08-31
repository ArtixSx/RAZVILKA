package cloudflareprovider

import (
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const writerLockFile = ".import.lock"
const writerLockMarker = "RAZVILKA cloudflare snapshot writer lock v1\n"

// acquireWriterLock serializes cooperating writers on one local filesystem.
// The marker is permanent: unlinking a locked file could give another process
// a different inode and therefore a second independent lock. Old O_EXCL-based
// writers also fail closed while this marker exists. It contains no secrets.
// Only the OS lock denotes a live writer; a PID or file age cannot prove that.
func acquireWriterLock(root *ownedfs.Root) (func(), error) {
	file, err := openWriterFile(root, true)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, statErr := root.Stat(writerLockFile)
		if statErr != nil || !validWriterFile(info) || info.Size() != int64(len(writerLockMarker)) {
			return nil, ErrBusy
		}
		file, err = openWriterFile(root, false)
	}
	if err != nil {
		return nil, ErrBusy
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close() // Also releases any acquired kernel lock.
		}
	}()
	info, err := file.Stat()
	if err != nil || !validWriterFile(info) || lockWriterFile(file) != nil {
		return nil, ErrBusy
	}
	// Check identity after locking, before reading/writing the protocol marker.
	current, err := root.Stat(writerLockFile)
	if err != nil || !os.SameFile(info, current) {
		return nil, ErrBusy
	}
	if created {
		// An interrupted first initialization leaves an empty/partial legacy-like
		// marker. Do not guess ownership or overwrite it on a subsequent attempt.
		if info.Size() != 0 {
			return nil, ErrBusy
		}
		if n, err := file.WriteString(writerLockMarker); err != nil || n != len(writerLockMarker) {
			return nil, ErrBusy
		}
		if file.Sync() != nil {
			return nil, ErrBusy
		}
	} else {
		marker, err := io.ReadAll(io.LimitReader(file, int64(len(writerLockMarker))+1))
		if err != nil || string(marker) != writerLockMarker {
			return nil, ErrBusy
		}
	}
	current, err = root.Stat(writerLockFile)
	if err != nil || !validWriterFile(current) || !os.SameFile(info, current) || current.Size() != int64(len(writerLockMarker)) {
		return nil, ErrBusy
	}
	keep = true
	return func() { unlockWriterFile(file); _ = file.Close() }, nil
}

func validWriterFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0)
}
