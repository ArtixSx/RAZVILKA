//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// Kernel comparison data only, never a resource/read interval/Start owner.
// The domain resource independently authenticates its original child and
// provider before and after these fixed procfs association reads.
type xrayDomainTCPKernelImage struct {
	argv       []byte
	exe        string
	executable os.FileInfo
}

func (i xrayDomainTCPKernelImage) matches(args []string, path string, original os.FileInfo) bool {
	return i.exe == path && sameXrayDomainTCPFile(original, i.executable) && bytes.Equal(i.argv, []byte(strings.Join(args, "\x00")+"\x00"))
}

func (i xrayDomainTCPKernelImage) same(other xrayDomainTCPKernelImage) bool {
	return i.exe == other.exe && bytes.Equal(i.argv, other.argv) && sameXrayDomainTCPFile(i.executable, other.executable)
}

func (p *xraySelectedTCPProc) domainKernelImage(ctx context.Context, expected netidentity.Identity) (xrayDomainTCPKernelImage, error) {
	if p == nil || xraySelectedTCPFinite(ctx) != nil || expected.Validate() != nil || p.current(ctx) != nil || p.network(ctx, expected) != nil {
		return xrayDomainTCPKernelImage{}, ErrXrayDomainTCPOriginal
	}
	boot, err := p.read(ctx, p.root, "sys/kernel/random/boot_id", 37)
	if err != nil || string(boot) != expected.BootID+"\n" {
		return xrayDomainTCPKernelImage{}, ErrXrayDomainTCPOriginal
	}
	argv, err := p.read(ctx, p.child, "cmdline", 64<<10)
	if err != nil || len(argv) == 0 || argv[len(argv)-1] != 0 {
		return xrayDomainTCPKernelImage{}, ErrXrayDomainTCPOriginal
	}
	exe, err := p.readlink(p.child, "exe")
	if err != nil || !filepath.IsAbs(exe) || filepath.Clean(exe) != exe || strings.ContainsAny(exe, "\x00\r\n") || strings.HasSuffix(exe, " (deleted)") {
		return xrayDomainTCPKernelImage{}, ErrXrayDomainTCPOriginal
	}
	fd, err := unix.Openat(p.child, "exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return xrayDomainTCPKernelImage{}, ErrXrayDomainTCPOriginal
	}
	f := os.NewFile(uintptr(fd), "[actual domain child executable association]")
	info, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil || !info.Mode().IsRegular() || p.network(ctx, expected) != nil || p.current(ctx) != nil {
		return xrayDomainTCPKernelImage{}, ErrXrayDomainTCPOriginal
	}
	return xrayDomainTCPKernelImage{argv: argv, exe: exe, executable: info}, nil
}

func (p *xraySelectedTCPProc) domainConfigFDInfo(ctx context.Context) (os.FileInfo, error) {
	if p == nil || xraySelectedTCPFinite(ctx) != nil || p.current(ctx) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	directory, err := p.open(ctx, p.child, "fd", true)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, "4", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	f := os.NewFile(uintptr(fd), "[closing actual domain child FD4 association]")
	info, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil || !info.Mode().IsRegular() || !p.procFile(directory, unix.S_IFDIR) || !p.sameMount(ctx, directory) || p.current(ctx) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	return info, nil
}
