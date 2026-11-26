//go:build linux

package components

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/unix"
)

// One reserved staging slot keeps repeated interrupted preparations bounded.
const masqueSidecarStage = ".masque-initial"
const masqueSidecarTarget = "sing-box"

// InstallInitialMASQUESidecar only prepares a file. It neither runs the
// downloaded program nor calls an init script or a package command.
func (m *Manager) InstallInitialMASQUESidecar(ctx context.Context, guard func(context.Context) error, admit func(context.Context, func() error) error) (Result, error) {
	result := Result{Component: MASQUESidecarComponent, Action: "install"}
	image, supported := masqueSidecarArtifacts[runtime.GOARCH]
	if m == nil || ctx == nil || guard == nil || admit == nil || m.Arch != runtime.GOARCH || !supported ||
		m.StateDir != filepath.Dir(installpath.ManagedUSQUE) {
		return result, NoMutation(ErrMASQUESidecarUnsupported)
	}
	current := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(ctx); err != nil {
			return err
		}
		for _, path := range []string{installpath.ManagedMASQUESingBox, "/opt/bin/sing-box", "/opt/usr/bin/sing-box"} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrComponentAlreadyInstalled, err)
			}
		}
		if _, err := exec.LookPath("sing-box"); !errors.Is(err, exec.ErrNotFound) {
			return errors.Join(ErrComponentAlreadyInstalled, err)
		}
		return nil
	}
	if err := current(ctx); err != nil {
		return result, NoMutation(err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := current(ctx); err != nil {
		return result, NoMutation(err)
	}
	state, err := usqueInstallState()
	if err != nil {
		return result, NoMutation(errors.Join(ErrMASQUESidecarUnsupported, err))
	}
	defer state.Close()
	componentDir := filepath.Base(m.StateDir)
	dir := filepath.Dir(installpath.ManagedMASQUESingBox)
	if err := state.MkdirAll(componentDir, 0700); err != nil {
		return result, NoMutation(err)
	}
	if info, err := state.Stat(componentDir); err != nil {
		return result, NoMutation(err)
	} else if _, trusted := hevRetainedOwner(info, true); !trusted {
		return result, NoMutation(ErrRecoveryAuthority)
	}
	release, err := m.fencePackageMutation()
	if err != nil {
		return result, NoMutation(err)
	}
	defer release()

	parent, err := ownedfs.Open(m.StateDir)
	if err != nil {
		return result, NoMutation(err)
	}
	defer parent.Close()
	child := filepath.Base(dir)
	if err := parent.MkdirAll(child, 0700); err != nil {
		return result, NoMutation(err)
	}
	if err := parent.Sync(); err != nil {
		return result, NoMutation(err)
	}
	if resolved, err := filepath.EvalSymlinks(dir); err != nil || resolved != dir {
		return result, NoMutation(errors.Join(ErrRecoveryAuthority, err))
	}
	root, err := ownedfs.Open(dir)
	if err != nil {
		return result, NoMutation(err)
	}
	defer root.Close()
	base := masqueSidecarArchiveBase(m.Arch)
	if err := publishMASQUESidecar(ctx, root, dir, image.binaryBytes, current, admit, func(dst io.Writer) error {
		url := "https://github.com/SagerNet/sing-box/releases/download/v" + masqueSidecarRelease + "/" + base + ".tar.gz"
		body, err := m.openReleaseAsset(ctx, url)
		if err != nil {
			return err
		}
		defer body.Close()
		return extractMASQUESidecar(body, dst, base+"/sing-box", image)
	}); err != nil {
		return result, err
	}
	result.OK = true
	result.Output = "installed verified MASQUE TUN companion " + masqueSidecarRelease
	return result, nil
}

func publishMASQUESidecar(ctx context.Context, root *ownedfs.Root, dir string, size int64, guard func(context.Context) error, admit func(context.Context, func() error) error, download func(io.Writer) error) (resultErr error) {
	anchor, err := root.RootInfo()
	if _, trusted := hevRetainedOwner(anchor, true); err != nil || !trusted {
		return NoMutation(errors.Join(ErrRecoveryAuthority, err))
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return NoMutation(err)
	}
	directory := os.NewFile(uintptr(dirFD), dir)
	defer directory.Close()
	held, err := directory.Stat()
	if _, trusted := hevRetainedOwner(held, true); err != nil || !trusted || !os.SameFile(anchor, held) {
		return NoMutation(errors.Join(ErrRecoveryAuthority, err))
	}
	if err := guard(ctx); err != nil {
		return NoMutation(err)
	}
	const stage = masqueSidecarStage
	const target = masqueSidecarTarget
	if _, err := root.Stat(target); !errors.Is(err, os.ErrNotExist) {
		return NoMutation(errors.Join(ErrComponentAlreadyInstalled, err))
	}
	if info, err := root.Stat(stage); err == nil {
		if _, trusted := hevRetainedOwner(info, false); !trusted || info.Size() > size || info.Mode().Perm() != 0600 && info.Mode().Perm() != 0500 {
			return NoMutation(ErrRecoveryAuthority)
		}
		if err := root.Remove(stage); err != nil {
			return NoMutation(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return NoMutation(err)
	}
	file, err := root.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return NoMutation(err)
	}
	created, err := file.Stat()
	staged := true
	defer func() {
		_ = file.Close()
		if staged {
			info, err := root.Stat(stage)
			if err != nil || created == nil || !os.SameFile(created, info) {
				resultErr = errors.Join(resultErr, ErrRecoveryAuthority, err)
				return
			}
			resultErr = errors.Join(resultErr, root.Remove(stage))
		}
	}()
	if err != nil {
		return NoMutation(err)
	}
	if err := download(file); err != nil {
		return NoMutation(err)
	}
	modeErr, syncErr := file.Chmod(0500), file.Sync()
	prepared, statErr := file.Stat()
	if err := errors.Join(modeErr, syncErr, statErr, file.Close()); err != nil {
		return NoMutation(err)
	}
	if err := guard(ctx); err != nil {
		return NoMutation(err)
	}
	return admit(ctx, func() error {
		if err := guard(ctx); err != nil {
			return NoMutation(err)
		}
		named, err := os.Lstat(dir)
		if _, trusted := hevRetainedOwner(named, true); err != nil || !trusted || !os.SameFile(anchor, named) {
			return NoMutation(errors.Join(ErrRecoveryAuthority, err))
		}
		info, err := root.Stat(stage)
		if _, trusted := hevRetainedOwner(info, false); err != nil || !trusted || !os.SameFile(prepared, info) ||
			info.Size() != size || info.Mode().Perm() != 0500 || !sameMASQUESidecarTime(prepared, info) {
			return NoMutation(errors.Join(ErrRecoveryAuthority, err))
		}
		if err := renameMASQUESidecar(dirFD); err != nil {
			return NoMutation(err)
		}
		staged = false
		if err := directory.Sync(); err != nil {
			return errors.Join(ErrUSQUEInstallPending, err)
		}
		return nil
	})
}

func renameMASQUESidecar(dirFD int) error {
	// ext4 has supported this flag since Linux 3.15. Even interruption before
	// directory fsync leaves no hard-link pair whose ownership is ambiguous.
	err := unix.Renameat2(dirFD, masqueSidecarStage, dirFD, masqueSidecarTarget, unix.RENAME_NOREPLACE)
	switch {
	case errors.Is(err, os.ErrExist):
		return errors.Join(ErrComponentAlreadyInstalled, err)
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
		return errors.Join(ErrMASQUESidecarUnsupported, err)
	default:
		return err
	}
}

func sameMASQUESidecarTime(a, b os.FileInfo) bool {
	before, okBefore := a.Sys().(*syscall.Stat_t)
	after, okAfter := b.Sys().(*syscall.Stat_t)
	return okBefore && okAfter && before.Ctim == after.Ctim && a.ModTime().Equal(b.ModTime())
}

func extractMASQUESidecar(src io.Reader, dst io.Writer, member string, image masqueSidecarArtifact) error {
	archiveSHA := sha256.New()
	archive := &io.LimitedReader{R: io.TeeReader(src, archiveSHA), N: image.archiveBytes + 1}
	compressed := bufio.NewReader(archive)
	zip, err := gzip.NewReader(compressed)
	if err != nil {
		return errors.Join(ErrMASQUESidecarIntegrity, err)
	}
	defer zip.Close()
	zip.Multistream(false)
	// Upstream ships extra material. Only one member may consume our storage.
	expanded := &io.LimitedReader{R: zip, N: 128 << 20}
	tarball := tar.NewReader(expanded)
	found := false
	for count := 0; ; count++ {
		header, err := tarball.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || count >= 16 {
			return errors.Join(ErrMASQUESidecarIntegrity, err)
		}
		if header.Name != member {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size != image.binaryBytes {
			return ErrMASQUESidecarIntegrity
		}
		binarySHA := sha256.New()
		n, err := io.CopyBuffer(io.MultiWriter(dst, binarySHA), tarball, make([]byte, 64<<10))
		if err != nil {
			return err
		}
		if n != image.binaryBytes || hex.EncodeToString(binarySHA.Sum(nil)) != image.binarySHA {
			return ErrMASQUESidecarIntegrity
		}
		found = true
	}
	// Consume the gzip footer and require exactly the reviewed compressed file.
	if _, err := io.Copy(io.Discard, expanded); err != nil {
		return errors.Join(ErrMASQUESidecarIntegrity, err)
	}
	_, tail := compressed.ReadByte()
	if !found || expanded.N == 0 || !errors.Is(tail, io.EOF) || archive.N != 1 || hex.EncodeToString(archiveSHA.Sum(nil)) != image.archiveSHA {
		return errors.Join(ErrMASQUESidecarIntegrity, tail)
	}
	return nil
}

// CheckInitialMASQUESidecarPublication settles directory durability before
// use. Executable bytes are checked separately by the calling adapter.
func CheckInitialMASQUESidecarPublication(ctx context.Context) error {
	return checkInitialUSQUEPublication(ctx, installpath.ManagedMASQUESingBox)
}
