package components

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// createManagedNFQWSPublicPath creates only missing payload ancestors. The
// installer's umask may be private; changing it would affect every goroutine.
// Instead, an exclusive mkdir is followed by identity/owner checks and chmod
// on the retained new directory descriptor. Existing directories (including an
// EEXIST race) are never repaired. The returned final root stays pinned until
// managedNFQWSRoot has independently opened and compared the published path.
func (m *Manager) createManagedNFQWSPublicPath(base *ownedfs.Root, path, relative string) (*os.Root, error) {
	if !filepath.IsLocal(relative) || filepath.Clean(relative) == "." {
		return nil, ErrManagedNFQWSBundle
	}
	current, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = current.Close()
		}
	}()
	original, originalErr := base.RootInfo()
	opened, openErr := current.Stat(".")
	if originalErr != nil || openErr != nil || !os.SameFile(original, opened) {
		return nil, errors.Join(ErrManagedNFQWSBundle, originalErr, openErr)
	}
	for _, part := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		before, err := current.Lstat(part)
		created := false
		if errors.Is(err, os.ErrNotExist) {
			// Never adopt/chmod an EEXIST winner: only this successful exclusive
			// mkdir can authorize widening the directory we subsequently pin.
			if err := current.Mkdir(part, 0700); err != nil {
				return nil, err
			}
			created = true
			before, err = current.Lstat(part)
		}
		if err != nil || !before.IsDir() || m.trustedManagedNFQWSNode(before) != nil || !created && !managedNFQWSPublicTraversal(before) {
			return nil, errors.Join(ErrManagedNFQWSBundle, err)
		}
		next, err := current.OpenRoot(part)
		if err != nil {
			return nil, err
		}
		if err := m.prepareManagedNFQWSChild(current, next, part, before, created); err != nil {
			_ = next.Close()
			return nil, err
		}
		if err := current.Close(); err != nil {
			_ = next.Close()
			return nil, err
		}
		current = next
	}
	keep = true
	return current, nil
}

func (m *Manager) prepareManagedNFQWSChild(parent, child *os.Root, name string, before os.FileInfo, created bool) error {
	held, err := child.Open(".")
	if err != nil {
		return err
	}
	defer held.Close()
	pinned, pinErr := held.Stat()
	after, pathErr := parent.Lstat(name)
	if pinErr != nil || pathErr != nil || !os.SameFile(before, pinned) || !os.SameFile(before, after) || !pinned.IsDir() || m.trustedManagedNFQWSNode(pinned) != nil {
		return errors.Join(ErrManagedNFQWSBundle, pinErr, pathErr)
	}
	if !created {
		if !managedNFQWSPublicTraversal(pinned) {
			return ErrManagedNFQWSBundle
		}
		return nil
	}
	if err := held.Chmod(0755); err != nil {
		return err
	}
	if err := syncBundleFile(held); err != nil {
		return err
	}
	fresh, err := held.Stat()
	if err != nil || !os.SameFile(before, fresh) || m.trustedManagedNFQWSNode(fresh) != nil || !updateModeMatches(fresh.Mode().Perm(), 0755) || !managedNFQWSPublicTraversal(fresh) {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	// Persist the new parent's entry separately from the child's mode/data.
	parentFile, err := parent.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(syncBundleFile(parentFile), parentFile.Close())
}
