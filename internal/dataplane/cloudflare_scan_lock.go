package dataplane

import (
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const cloudflareScanLockFile = ".scan.lock"
const cloudflareScanLockMarker = "RAZVILKA isolated cloudflare scan lock v1\n"

// acquireCloudflareScanLock serializes cooperating processes on the fixed
// scanner interface, route table and rule priority. The marker is permanent:
// unlinking it while locked could create a second independently locked inode.
func acquireCloudflareScanLock(root *ownedfs.Root) (func(), error) {
	file, err := openCloudflareScanLockFile(root, true)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, statErr := root.Stat(cloudflareScanLockFile)
		if statErr != nil || !validCloudflareScanLockFile(info) || info.Size() != int64(len(cloudflareScanLockMarker)) {
			return nil, errors.New("unsafe Cloudflare scan lock")
		}
		file, err = openCloudflareScanLockFile(root, false)
	}
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !validCloudflareScanLockFile(info) || lockCloudflareScanFile(file) != nil {
		return nil, errors.New("lock Cloudflare scanner")
	}
	current, err := root.Stat(cloudflareScanLockFile)
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("Cloudflare scan lock changed")
	}
	if created {
		if info.Size() != 0 {
			return nil, errors.New("Cloudflare scan lock is not empty")
		}
		if n, writeErr := file.WriteString(cloudflareScanLockMarker); writeErr != nil || n != len(cloudflareScanLockMarker) || file.Sync() != nil {
			return nil, errors.New("initialize Cloudflare scan lock")
		}
	} else {
		marker, readErr := io.ReadAll(io.LimitReader(file, int64(len(cloudflareScanLockMarker))+1))
		if readErr != nil || string(marker) != cloudflareScanLockMarker {
			return nil, errors.New("unknown Cloudflare scan lock")
		}
	}
	current, err = root.Stat(cloudflareScanLockFile)
	if err != nil || !validCloudflareScanLockFile(current) || !os.SameFile(info, current) || current.Size() != int64(len(cloudflareScanLockMarker)) {
		return nil, errors.New("Cloudflare scan lock changed")
	}
	keep = true
	return func() { unlockCloudflareScanFile(file); _ = file.Close() }, nil
}

func validCloudflareScanLockFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0)
}
