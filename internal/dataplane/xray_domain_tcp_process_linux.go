//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// Private comparison reader only. The future original publisher must surround
// it with source, typed-map and authored-journal bookends; no observation DTO
// or successfully read process can issue an execution or a Ready runtime.
func (r *XrayDomainTCPExecutionResource) observeDomainProcess(ctx context.Context) (xraySelectedTCPProcessObservation, error) {
	if r.domainProcessCurrent(ctx) != nil || r.scope.networkIdentity == nil || r.scope.networkIdentity.provider == nil {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	var observed xraySelectedTCPProcessObservation
	err := r.scope.networkIdentity.provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != r.definition.NetworkIdentity || r.domainProcessCurrent(held) != nil {
			return ErrXrayDomainTCPOriginal
		}
		proc, err := openXraySelectedTCPProc(held, r.child.pid)
		if err != nil {
			return err
		}
		defer proc.close()
		before, err := r.readDomainProcess(held, proc, current)
		if err != nil {
			return err
		}
		after, err := r.readDomainProcess(held, proc, current)
		if err != nil || !before.same(after) || proc.current(held) != nil || r.domainProcessCurrent(held) != nil {
			return ErrXrayDomainTCPOriginal
		}
		observed = after
		return nil
	})
	if err != nil || r.domainProcessCurrent(ctx) != nil {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	return observed, nil
}

func (r *XrayDomainTCPExecutionResource) readDomainProcess(ctx context.Context, proc *xraySelectedTCPProc, network netidentity.Identity) (xraySelectedTCPProcessObservation, error) {
	if r.domainProcessCurrent(ctx) != nil || proc == nil || proc.pid != r.child.pid || network != r.definition.NetworkIdentity || network.Validate() != nil || r.filesCurrent(ctx) != nil {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	p := r.child
	args := []string{r.executable.path, "run", "-config", "/proc/self/fd/4"}
	if p.image.path != "/proc/self/fd/3" || p.image.dir != r.rootPath || !slices.Equal(p.image.args, args) || !slices.Equal(p.image.env, xraySelectedTCPNativeEnvironment()) ||
		len(p.image.extras) != 2 || p.image.extras[0] != r.executable.file || p.image.extras[1] != r.config {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	stat, err := proc.read(ctx, proc.child, "stat", 8192)
	start, parent, group, parseErr := xraySelectedTCPStat(stat, p.pid)
	if err != nil || parseErr != nil || parent != p.parent || group != p.pid {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	argv, err := proc.read(ctx, proc.child, "cmdline", 64<<10)
	if err != nil || !bytes.Equal(argv, []byte(strings.Join(args, "\x00")+"\x00")) {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	boot, err := proc.read(ctx, proc.root, "sys/kernel/random/boot_id", 37)
	if err != nil || string(boot) != network.BootID+"\n" || proc.network(ctx, network) != nil {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	exe, err := proc.readlink(proc.child, "exe")
	if err != nil || exe != r.executable.path || !filepath.IsAbs(exe) || filepath.Clean(exe) != exe || strings.ContainsAny(exe, "\x00\r\n") {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	fd, err := unix.Openat(proc.child, "exe", unix.O_PATH|unix.O_CLOEXEC, 0) // Only the actual child's kernel executable link.
	if err != nil {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	f := os.NewFile(uintptr(fd), "[actual original domain Xray executable]")
	executable, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil || !sameXrayDomainTCPFile(r.executable.info, executable) {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	if err := r.readDomainConfigFD(ctx, proc); err != nil {
		return xraySelectedTCPProcessObservation{}, err
	}
	closing, err := proc.read(ctx, proc.child, "stat", 8192)
	closeStart, closeParent, closeGroup, parseErr := xraySelectedTCPStat(closing, p.pid)
	if err != nil || parseErr != nil || closeStart != start || closeParent != parent || closeGroup != group ||
		proc.current(ctx) != nil || r.domainProcessCurrent(ctx) != nil || r.filesCurrent(ctx) != nil {
		return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
	}
	argumentHash := sha256.Sum256(argv)
	return xraySelectedTCPProcessObservation{pid: p.pid, parent: parent, group: group, boot: network.BootID, start: start, exe: exe,
		argumentsSHA256: hex.EncodeToString(argumentHash[:]), configSHA256: r.definition.ConfigSHA256,
		executable: executable, config: r.configInfo, network: network}, nil
}

func sameXrayDomainTCPFile(original, current os.FileInfo) bool {
	return original != nil && current != nil && current.Mode().IsRegular() && os.SameFile(original, current) &&
		original.Size() == current.Size() && original.Mode() == current.Mode() && original.ModTime().Equal(current.ModTime())
}

// No config path from a process DTO is accepted. The named domain config and
// the held authored FD have already been compared; FD4 must name that exact
// inode and its complete bytes, with closing held-FD/process/procfs bookends.
func (r *XrayDomainTCPExecutionResource) readDomainConfigFD(ctx context.Context, proc *xraySelectedTCPProc) error {
	if r.domainProcessCurrent(ctx) != nil || proc == nil || proc.pid != r.child.pid || r.filesCurrent(ctx) != nil {
		return ErrXrayDomainTCPOriginal
	}
	directory, err := proc.open(ctx, proc.child, "fd", true)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, "4", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrXrayDomainTCPOriginal
	}
	f := os.NewFile(uintptr(fd), "[actual original domain Xray config FD4]")
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !sameXrayDomainTCPFile(r.configInfo, before) {
		return ErrXrayDomainTCPOriginal
	}
	data, err := xraySelectedTCPReadFD(ctx, fd, 1<<20)
	defer clear(data)
	hash := sha256.Sum256(data)
	after, statErr := f.Stat()
	closing, originalErr := r.config.Stat()
	if err != nil || statErr != nil || originalErr != nil || int64(len(data)) != r.configInfo.Size() ||
		!sameXrayDomainTCPFile(before, after) || !sameXrayDomainTCPFile(r.configInfo, closing) ||
		hex.EncodeToString(hash[:]) != r.definition.ConfigSHA256 || !proc.procFile(directory, unix.S_IFDIR) || !proc.sameMount(ctx, directory) ||
		proc.current(ctx) != nil || r.domainProcessCurrent(ctx) != nil {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}
