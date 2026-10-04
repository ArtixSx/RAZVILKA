package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Fixed private-file participants write mode0600. Bytes/Exists equality is
// insufficient: a no-op restore must refuse widened permissions or a foreign
// owner. Observe the actual opened descriptor and pinned leaf identity; never
// chmod/chown in a read-only proof or start a panel to repair its token gate.
func (a *SelfUpdateFileAdapter) verifyPrivateFileMetadata(ctx context.Context, path string, wantedPresent bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.owned == nil {
		return ErrFileProtocol
	}
	if err := a.owned(filepath.Dir(path)); err != nil {
		return err
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) && !wantedPresent {
		return ctx.Err()
	}
	if err != nil || !wantedPresent || !before.Mode().IsRegular() {
		return ErrFileProtocol
	}
	if err := a.owned(path); err != nil {
		return err
	}
	file, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) || !actual.Mode().IsRegular() || actual.Mode().Perm() != 0600 || actual.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrFileProtocol
	}
	if err := checkPrivateDescriptorOwner(actual); err != nil {
		return err
	}
	fresh, err := root.Stat(name)
	if err != nil || !os.SameFile(actual, fresh) || fresh.Mode() != actual.Mode() {
		return ErrFileProtocol
	}
	if err := checkPrivateDescriptorOwner(fresh); err != nil {
		return err
	}
	return ctx.Err()
}
