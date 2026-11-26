//go:build linux

package components

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// InstallInitialUSQUE publishes only the pinned executable below the original
// component state root. The caller retains the Auto permit and the exact
// service's current review. Registration and route activation are separate.
func (m *Manager) InstallInitialUSQUE(ctx context.Context, guard func(context.Context) error) (Result, error) {
	result := Result{Component: "usque", Action: "install"}
	if m == nil || ctx == nil || guard == nil || m.StateDir != filepath.Dir(installpath.ManagedUSQUE) || m.Arch != runtime.GOARCH || reviewedUSQUEArchives[m.Arch] == "" {
		return result, NoMutation(ErrUSQUEInstallUnsupported)
	}
	current := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		if err := guard(c); err != nil {
			return err
		}
		for _, path := range []string{"/opt/etc/init.d/S51usque", "/opt/bin/usque", "/opt/usr/bin/usque"} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrUSQUEVendorOwner, err)
			}
		}
		return nil
	}
	if err := current(ctx); err != nil {
		return result, NoMutation(err)
	}
	if _, err := os.Lstat(installpath.ManagedUSQUE); !errors.Is(err, os.ErrNotExist) {
		return result, NoMutation(errors.Join(ErrComponentAlreadyInstalled, err))
	}
	name := "usque_" + reviewedUSQUERelease + "_linux_" + m.Arch + ".zip"
	url := "https://github.com/Diniboy1123/usque/releases/download/v" + reviewedUSQUERelease + "/" + name
	archive, err := m.download(ctx, url, 6<<20)
	if err != nil {
		return result, NoMutation(err)
	}
	binary, err := reviewedUSQUEBinary(m.Arch, archive)
	if err != nil {
		return result, NoMutation(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := current(ctx); err != nil {
		return result, NoMutation(err)
	}
	state, err := usqueInstallState()
	if err != nil {
		return result, NoMutation(err)
	}
	defer state.Close()
	if err := state.MkdirAll(filepath.Base(m.StateDir), 0700); err != nil {
		return result, NoMutation(err)
	}
	release, err := m.fencePackageMutation()
	if err != nil {
		return result, NoMutation(err)
	}
	defer release()
	if err := publishInitialUSQUE(ctx, installpath.ManagedUSQUE, binary, current); err != nil {
		return result, err
	}
	result.OK = true
	result.Output = "installed verified USQUE " + reviewedUSQUERelease
	return result, nil
}

func usqueInstallState() (*ownedfs.Root, error) {
	path := installpath.State
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return nil, errors.Join(ErrUSQUEInstallUnsupported, err)
	}
	state, err := ownedfs.Open(path)
	if err != nil {
		return nil, errors.Join(ErrUSQUEInstallUnsupported, err)
	}
	info, err := state.RootInfo()
	if _, trusted := hevRetainedOwner(info, true); err != nil || !trusted {
		_ = state.Close()
		return nil, errors.Join(ErrUSQUEInstallUnsupported, err)
	}
	return state, nil
}

// CheckInitialUSQUEPublication settles a previous uncertain directory sync
// before registration can use the private core. The caller separately proves
// the executable bytes and exact runtime source. A staging hard link from an
// interrupted publication prevents confirmation.
func (m *Manager) CheckInitialUSQUEPublication(ctx context.Context) error {
	if m == nil || ctx == nil || m.StateDir != filepath.Dir(installpath.ManagedUSQUE) || !m.mu.TryLock() {
		return ErrUSQUEInstallPending
	}
	defer m.mu.Unlock()
	return checkInitialUSQUEPublication(ctx, installpath.ManagedUSQUE)
}

func checkInitialUSQUEPublication(ctx context.Context, target string) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	dir := filepath.Dir(target)
	if real, err := filepath.EvalSymlinks(dir); err != nil || real != dir {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	root, err := ownedfs.Open(dir)
	if err != nil {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	defer root.Close()
	anchor, err := root.RootInfo()
	if _, trusted := hevRetainedOwner(anchor, true); err != nil || !trusted {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	before, err := root.Stat(filepath.Base(target))
	if _, trusted := hevRetainedOwner(before, false); err != nil || !trusted || before.Mode().Perm() != 0500 {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	if err := root.Sync(); err != nil {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	after, afterErr := os.Lstat(target)
	named, namedErr := os.Lstat(dir)
	if _, trusted := hevRetainedOwner(after, false); afterErr != nil || namedErr != nil || !trusted ||
		!os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		!os.SameFile(anchor, named) || anchor.Mode() != named.Mode() || ctx.Err() != nil {
		return errors.Join(ErrUSQUEInstallPending, afterErr, namedErr, ctx.Err())
	}
	return nil
}

// The hard link publishes a complete single file atomically and fails if
// either an earlier attempt or an unrelated owner already created the name.
func publishInitialUSQUE(ctx context.Context, target string, binary []byte, guard func(context.Context) error) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return NoMutation(err)
	}
	dir := filepath.Dir(target)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != dir {
		return NoMutation(errors.Join(ErrRecoveryAuthority, err))
	}
	root, err := ownedfs.Open(dir)
	if err != nil {
		return NoMutation(err)
	}
	defer func() { _ = root.Close() }()
	anchor, err := root.RootInfo()
	if _, trusted := hevRetainedOwner(anchor, true); err != nil || !trusted {
		return NoMutation(errors.Join(ErrRecoveryAuthority, err))
	}
	name := filepath.Base(target)
	temp := ".usque-core-" + rand.Text()
	file, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return NoMutation(err)
	}
	staged := true
	defer func() {
		if staged {
			resultErr = errors.Join(resultErr, root.Remove(temp))
		}
	}()
	_, writeErr := file.Write(binary)
	modeErr := file.Chmod(0500)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, modeErr, syncErr, file.Close()); err != nil {
		return NoMutation(err)
	}
	if err := guard(ctx); err != nil {
		return NoMutation(err)
	}
	named, err := os.Lstat(dir)
	if err != nil || !os.SameFile(anchor, named) || anchor.Mode() != named.Mode() {
		return NoMutation(errors.Join(ErrRecoveryAuthority, err))
	}
	if err := root.Link(temp, name); err != nil {
		if errors.Is(err, os.ErrExist) {
			err = errors.Join(ErrComponentAlreadyInstalled, err)
		}
		return NoMutation(err)
	}
	if err := root.Remove(temp); err != nil {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	staged = false
	if err := root.Sync(); err != nil {
		return errors.Join(ErrUSQUEInstallPending, err)
	}
	return nil
}
