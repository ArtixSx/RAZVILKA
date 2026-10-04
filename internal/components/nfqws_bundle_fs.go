package components

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// PreflightManagedNFQWS checks only the fixed owned filesystem contract. It
// creates no journal/root, downloads nothing, and confers no runtime authority.
// Install repeats these checks after acquiring the existing writer lease.
func (m *Manager) PreflightManagedNFQWS(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	base, relative, err := m.managedNFQWSLocation()
	if err != nil {
		return err
	}
	if err := m.publicManagedNFQWSPath(filepath.Join(base, relative), true); err != nil {
		return err
	}
	root, err := ownedfs.Open(base)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Check(relative); err != nil {
		return err
	}
	return ctx.Err()
}

// Only package tests set this boundary from testing.TempDir. Pin its inode,
// keep it private, and exempt only that container and its outside ancestors
// from public traversal. Every descendant still needs trusted ownership and
// immutable-to-group/other modes. No ancestor is chmod'ed for a fixture.
type managedNFQWSFixtureBoundary struct {
	path string
	info os.FileInfo
}

func (m *Manager) trustedManagedNFQWSNode(info os.FileInfo) error {
	if info == nil || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrManagedNFQWSBundle
	}
	return trustedManagedNFQWSOwner(info, m.nfqwsFixture != nil)
}

// Production requires a root-euid writer, root-owned real canonical ancestors,
// other-execute, and no group/other write (including sticky /tmp). Hash readback
// does not exclude another root-euid writer; the runtime owner must do that.
// missing is used only for preflight before creating any releases ancestor.
func (m *Manager) publicManagedNFQWSPath(path string, missing bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrManagedNFQWSBundle
	}
	boundary := m.nfqwsFixture
	if boundary != nil {
		rel, err := filepath.Rel(boundary.path, path)
		info, statErr := os.Lstat(boundary.path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || statErr != nil || boundary.info == nil || !os.SameFile(info, boundary.info) || !info.IsDir() || m.trustedManagedNFQWSNode(info) != nil {
			return ErrManagedNFQWSBundle
		}
	}
	for {
		info, err := os.Lstat(path)
		if missing && errors.Is(err, os.ErrNotExist) {
			// Walk up to the existing ancestor, checking it before mkdir.
		} else if err != nil || !info.IsDir() || m.trustedManagedNFQWSNode(info) != nil {
			return fmt.Errorf("%w: unsafe managed payload ancestor %s (%s)", errors.Join(ErrManagedNFQWSBundle, err), path, managedNFQWSNodeDescription(info))
		} else if boundary != nil && path == boundary.path {
			return nil
		} else if !managedNFQWSPublicTraversal(info) {
			return fmt.Errorf("%w: managed payload ancestor %s does not allow runtime traversal", ErrManagedNFQWSBundle, path)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
