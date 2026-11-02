//go:build linux

package components

import (
	"context"
	"os"
	"syscall"
)

func mihomoLiveReadFileFingerprint(file *os.File) (mihomoLiveReadFileID, error) {
	if file == nil {
		return mihomoLiveReadFileID{}, ErrMihomoLiveOwner
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128<<20 {
		return mihomoLiveReadFileID{}, ErrMihomoLiveOwner
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return mihomoLiveReadFileID{}, ErrMihomoLiveOwner
	}
	// ATIM is deliberately excluded: normal read/hash operations may change it.
	return mihomoLiveReadFileID{device: uint64(stat.Dev), inode: uint64(stat.Ino), rdev: uint64(stat.Rdev), links: uint64(stat.Nlink), mode: uint32(stat.Mode), uid: stat.Uid, gid: stat.Gid, size: stat.Size, blocks: stat.Blocks, blocksize: int64(stat.Blksize), mtimeSeconds: int64(stat.Mtim.Sec), mtimeNanos: int64(stat.Mtim.Nsec), ctimeSeconds: int64(stat.Ctim.Sec), ctimeNanos: int64(stat.Ctim.Nsec)}, nil
}

func (n *mihomoLiveNativeLinux) readFingerprint(ctx context.Context) (mihomoLiveReadFileID, error) {
	if err := mihomoLiveFinite(ctx); err != nil {
		return mihomoLiveReadFileID{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.closeErr != nil || n.owner == nil || n.owner.self != n.owner {
		return mihomoLiveReadFileID{}, ErrMihomoLiveOwner
	}
	return mihomoLiveReadFileFingerprint(n.binary)
}
