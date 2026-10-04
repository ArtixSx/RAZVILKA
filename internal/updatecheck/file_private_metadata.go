package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// A single descriptor binds bytes and metadata. The CAS keeps it open through
// effect admission so widened mode or a substituted leaf cannot supply proof
// for another inode. No read or effect silently repairs private metadata.
type privateFileObservation struct {
	root  *os.Root
	name  string
	file  *os.File
	info  os.FileInfo
	image restorejournal.Image
}

func (a *SelfUpdateFileAdapter) openPrivateFileRoot(path string) (*os.Root, error) {
	if a.owned == nil || !filepath.IsAbs(path) {
		return nil, ErrFileProtocol
	}
	parent := filepath.Dir(path)
	if err := a.owned(parent); err != nil {
		return nil, err
	}
	before, err := os.Lstat(parent)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrFileProtocol
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(before, actual) {
		root.Close()
		return nil, ErrFileProtocol
	}
	if err := a.owned(path); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func (a *SelfUpdateFileAdapter) readPrivateFileImage(ctx context.Context, path string) (restorejournal.Image, error) {
	root, err := a.openPrivateFileRoot(path)
	if err != nil {
		return restorejournal.Image{}, err
	}
	defer root.Close()
	observation, err := observePrivateFile(ctx, root, filepath.Base(path))
	if err != nil {
		return restorejournal.Image{}, err
	}
	defer observation.close()
	return observation.image, nil
}

// Compatibility helper for metadata-only regression cases. Production reads
// use readPrivateFileImage; they never certify bytes from a different fd.
func (a *SelfUpdateFileAdapter) verifyPrivateFileMetadata(ctx context.Context, path string, wantedPresent bool) error {
	image, err := a.readPrivateFileImage(ctx, path)
	if err != nil || image.Exists != wantedPresent {
		return errors.Join(ErrFileProtocol, err)
	}
	return nil
}

func observePrivateFile(ctx context.Context, root *os.Root, name string) (*privateFileObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if root == nil || !filepath.IsLocal(name) || filepath.Base(name) != name {
		return nil, ErrFileProtocol
	}
	observation := &privateFileObservation{root: root, name: name}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return observation, observation.verify(ctx)
	}
	if err != nil || !before.Mode().IsRegular() || before.Size() > restorejournal.MaxImageBytes {
		return nil, ErrFileProtocol
	}
	file, err := openPrivateReadOnly(root, name)
	if err != nil {
		return nil, err
	}
	observation.file = file
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		observation.close()
		return nil, ErrFileProtocol
	}
	observation.info = actual
	observation.image.Exists = true
	if err := observation.verify(ctx); err != nil {
		observation.close()
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, restorejournal.MaxImageBytes+1))
	if err != nil || len(data) > restorejournal.MaxImageBytes {
		observation.close()
		return nil, ErrFileProtocol
	}
	observation.image.Data = data
	if err := observation.verify(ctx); err != nil {
		observation.close()
		return nil, err
	}
	return observation, nil
}

func (observation *privateFileObservation) close() {
	if observation.file != nil {
		_ = observation.file.Close()
	}
}

// Called again inside the short effect admission. This observes only fd/leaf
// metadata and identity: no payload read, fsync, lease or Store lock here.
func (observation *privateFileObservation) verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !observation.image.Exists {
		_, err := observation.root.Lstat(observation.name)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return ErrFileProtocol
	}
	actual, err := observation.file.Stat()
	if err != nil {
		return ErrFileProtocol
	}
	fresh, err := observation.root.Lstat(observation.name)
	if err != nil {
		return ErrFileProtocol
	}
	for _, info := range []os.FileInfo{actual, fresh} {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !os.SameFile(observation.info, info) || info.Mode() != observation.info.Mode() || info.Size() != observation.info.Size() || !info.ModTime().Equal(observation.info.ModTime()) || checkPrivateDescriptorOwner(info) != nil {
			return ErrFileProtocol
		}
	}
	return ctx.Err()
}
