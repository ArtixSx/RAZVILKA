//go:build linux

package restorejournal

import (
	"os"
	"syscall"
)

func artifactReadFingerprint(info os.FileInfo) (artifactReadFileID, error) {
	if info == nil || !info.Mode().IsRegular() {
		return artifactReadFileID{}, ErrInvalid
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s == nil {
		return artifactReadFileID{}, ErrInvalid
	}
	return artifactReadFileID{device: uint64(s.Dev), inode: uint64(s.Ino), rdev: uint64(s.Rdev), links: uint64(s.Nlink), mode: uint32(s.Mode), uid: s.Uid, gid: s.Gid, size: s.Size, blocks: s.Blocks, blocksize: int64(s.Blksize), mtimeSeconds: int64(s.Mtim.Sec), mtimeNanos: int64(s.Mtim.Nsec), ctimeSeconds: int64(s.Ctim.Sec), ctimeNanos: int64(s.Ctim.Nsec)}, nil
}
