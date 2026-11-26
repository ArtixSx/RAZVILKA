//go:build linux

package updatecheck

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func externalBootstrapFileFlags() int { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }

func externalBootstrapProgramInfo() (os.FileInfo, error) {
	path, err := os.Executable()
	if err != nil || !filepath.IsAbs(path) || checkRootOwnedPath(path) != nil {
		return nil, ErrExternalBootstrap
	}
	info, err := os.Stat("/proc/self/exe")
	current, currentErr := os.Lstat(path)
	if err != nil || currentErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, current) || info.Size() <= 0 || info.Size() > MaximumBinaryBytes {
		return nil, ErrExternalBootstrap
	}
	return info, nil
}

func externalBootstrapProcesses(ctx context.Context, deployment Deployment) (fileProcess, fileProcess, string, error) {
	var zero fileProcess
	if err := ctx.Err(); err != nil {
		return zero, zero, "", err
	}
	root, err := ownedfs.Open(installpath.Run)
	if err != nil {
		return zero, zero, "", err
	}
	data, err := root.ReadLimited("razvilka.pid", 32)
	root.Close()
	pid, pidErr := externalBootstrapPID(data)
	if err != nil || pidErr != nil || checkProductionPID(pid, deployment.Executable) != nil || pid == os.Getpid() {
		return zero, zero, "", ErrExternalBootstrap
	}
	panel, err := fileProcessAt(pid)
	if err != nil {
		return zero, zero, "", err
	}
	sha, err := hashRegularFile(deployment.Executable, MaximumBinaryBytes)
	if err != nil || panel.ExecutableSHA256 != sha {
		return zero, zero, "", ErrExternalBootstrap
	}
	self, err := fileProcessAt(os.Getpid())
	if err != nil {
		return zero, zero, "", err
	}
	if _, err := externalBootstrapProgramInfo(); err != nil {
		return zero, zero, "", err
	}
	closing, err := fileProcessAt(pid)
	if err != nil || closing != panel || self.Boot != panel.Boot || checkProductionPID(pid, deployment.Executable) != nil || ctx.Err() != nil {
		return zero, zero, "", ErrExternalBootstrap
	}
	return self, panel, sha, nil
}

func externalBootstrapEntryMatches(ctx context.Context, id, archivePath, archiveSHA string, self fileProcess) error {
	fact, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil || fact.Process != self || len(fact.Args) != 5 || fact.Args[1] != "self-update-bootstrap-old193" || fact.Args[2] != id || fact.Args[3] != archivePath || fact.Args[4] != archiveSHA {
		return ErrExternalBootstrap
	}
	return nil
}
