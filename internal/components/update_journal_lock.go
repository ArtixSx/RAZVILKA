package components

import (
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Keep the inode permanently. Only the kernel lock proves a live writer;
// neither an old PID nor an old modification time authorizes another writer.
func lockUpdateWriter(root *ownedfs.Root) (func(), error) {
	const name = ".writer.lock"
	const marker = "RAZVILKA component update writer v1\n"
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|updateFileFlags(), 0o600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		f, err = root.OpenFile(name, os.O_RDWR|updateFileFlags(), 0o600)
	}
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) || lockUpdateFile(f) != nil {
		return nil, errors.New("component journal writer busy or unsafe")
	}
	current, err := root.Stat(name)
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("component journal writer changed")
	}
	if created {
		if _, err := f.WriteString(marker); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
		if err := syncUpdateDirectory(root); err != nil {
			return nil, err
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(f, int64(len(marker))+1))
		if err != nil || string(data) != marker {
			return nil, errors.New("unknown component journal writer marker")
		}
	}
	keep = true
	return func() { _ = f.Close() }, nil
}
