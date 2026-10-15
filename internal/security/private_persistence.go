package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type privateDirectorySync func(*ownedfs.Root) error

// writePrivateFile replaces an owner-only file, syncing its contents before
// rename and the held parent directory afterwards.
func writePrivateFile(path string, data []byte) error {
	return writePrivateFileWithSync(path, data, nil)
}

func privateParent(path string) (*ownedfs.Root, error) {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create private directory: %w", err)
	}
	return ownedfs.Open(dir)
}

func writePrivateFileWithSync(path string, data []byte, syncDir privateDirectorySync) error {
	root, err := privateParent(path)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.WriteAtomic(filepath.Base(path), data, 0o600); err != nil {
		return fmt.Errorf("commit private file: %w", err)
	}
	return syncPrivateParent(root, syncDir)
}

// A failed rewrite may fall back to removing the session file. Absence also
// needs directory sync: an earlier unlink may have succeeded before a sync
// error, so merely observing ENOENT is not a durable revocation receipt.
func removePrivateFileWithSync(path string, syncDir privateDirectorySync) error {
	root, err := privateParent(path)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(filepath.Base(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove private file: %w", err)
	}
	return syncPrivateParent(root, syncDir)
}

func syncPrivateParent(root *ownedfs.Root, syncDir privateDirectorySync) error {
	if syncDir == nil {
		syncDir = syncPrivateDirectory
	}
	if err := syncDir(root); err != nil {
		return fmt.Errorf("sync private directory: %w", err)
	}
	return nil
}
