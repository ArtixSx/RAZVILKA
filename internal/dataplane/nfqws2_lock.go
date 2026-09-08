package dataplane

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const nfqws2LockMarker = "RAZVILKA shared NFQWS2 resource lock v1\n"

// Locks are tied to shared resource paths, not the instance StateRoot. Keep
// each marker inode permanently: unlinking it permits a second concurrent lock.
func (a *NFQWS2Adapter) lockResources() (func(), error) {
	paths := []string{a.ConfigPath, a.InitPath, a.UserListPath, a.IPSetListPath}
	sort.Strings(paths)
	unlocks := []func(){}
	release := func() {
		for index := len(unlocks) - 1; index >= 0; index-- {
			unlocks[index]()
		}
	}
	previous := ""
	for _, path := range paths {
		if path == previous {
			continue
		}
		previous = path
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			release()
			return nil, errors.New("NFQWS2 resource path is not canonical")
		}
		root, err := ownedfs.Open(filepath.Dir(path))
		if err != nil {
			release()
			return nil, err
		}
		unlock, err := acquireNFQWS2ResourceLock(root, "."+filepath.Base(path)+".razvilka-lock")
		_ = root.Close()
		if err != nil {
			release()
			return nil, err
		}
		unlocks = append(unlocks, unlock)
	}
	return release, nil
}

func acquireNFQWS2ResourceLock(root *ownedfs.Root, name string) (func(), error) {
	file, err := openNFQWS2LockFile(root, name, true)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, statErr := root.Stat(name)
		if statErr != nil || !validCloudflareScanLockFile(info) || info.Size() != int64(len(nfqws2LockMarker)) {
			return nil, errors.New("NFQWS2 shared resource lock is unsafe")
		}
		file, err = openNFQWS2LockFile(root, name, false)
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
	// These platform primitives are generic nonblocking flock/LockFileEx.
	if err != nil || !validCloudflareScanLockFile(info) || lockCloudflareScanFile(file) != nil {
		return nil, errors.New("NFQWS2 shared resource is busy")
	}
	current, err := root.Stat(name)
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("NFQWS2 shared resource lock changed")
	}
	if created {
		if info.Size() != 0 {
			return nil, errors.New("NFQWS2 new resource lock is not empty")
		}
		if n, err := file.WriteString(nfqws2LockMarker); err != nil || n != len(nfqws2LockMarker) || file.Sync() != nil {
			return nil, errors.New("NFQWS2 resource lock initialization failed")
		}
	} else {
		marker, err := io.ReadAll(io.LimitReader(file, int64(len(nfqws2LockMarker))+1))
		if err != nil || string(marker) != nfqws2LockMarker {
			return nil, errors.New("NFQWS2 resource lock marker is unknown")
		}
	}
	keep = true
	return func() { unlockCloudflareScanFile(file); _ = file.Close() }, nil
}
