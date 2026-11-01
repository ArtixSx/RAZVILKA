//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"golang.org/x/sys/unix"
)

// Only platform classification differs in this native fixture build. Actual
// uname/os-release, tools/dependencies, original provider and complete backend
// inventories, registered adapters and every inactivity observation stay real.
type runtimeInactivityNativeFixture struct {
	outer  *os.File
	review string
}

func runtimeInactivityFixture(ctx context.Context, facts selfUpdateRuntimePlatformFacts) (*runtimeInactivityNativeFixture, error) {
	path := os.Getenv("RAZVILKA_RUNTIME_NATIVE_REVIEW")
	if path == "" {
		return nil, nil
	}
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || facts.system != "Linux" || facts.arch != "amd64" || facts.machine != "x86_64" || facts.distribution != "ubuntu" || facts.version == "" || facts.metadataOwner == [32]byte{} || os.Getenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD") != "3" {
		return nil, dataplane.ErrRuntimeInactivity
	}
	root := os.Getenv("TMPDIR")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || path != filepath.Join(root, "runtime-native-tool-review.json") {
		return nil, dataplane.ErrRuntimeInactivity
	}
	for i, p := range []string{root, path} {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || i == 0 && !info.IsDir() || i == 1 && (!info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096) {
			return nil, dataplane.ErrRuntimeInactivity
		}
	}
	fd, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &runtimeInactivityNativeFixture{outer: os.NewFile(uintptr(fd), "original outer net namespace"), review: path}, nil
}
func (f *runtimeInactivityNativeFixture) Acquire(lifetime context.Context, provider *netidentity.Provider) (*startuptools.Lease, error) {
	if f == nil || f.outer == nil {
		return nil, dataplane.ErrRuntimeInactivity
	}
	return startuptools.AcquireNativeFixturePolicyWithOuterNetFD(lifetime, provider, f.review, f.outer)
}
func (f *runtimeInactivityNativeFixture) Close() error {
	if f == nil || f.outer == nil {
		return nil
	}
	file := f.outer
	f.outer = nil
	return file.Close()
}
