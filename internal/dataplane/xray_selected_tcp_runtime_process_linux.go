//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/unix"
)

func xraySelectedTCPWaitResult(pid int, state *os.ProcessState, waitErr error) bool {
	if pid <= 1 || state == nil || state.Pid() != pid {
		return false
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Exited() && !status.Signaled() {
		return false
	}
	if waitErr == nil {
		return state.Success()
	}
	var exit *exec.ExitError
	return !state.Success() && errors.As(waitErr, &exit) && exit.ProcessState == state
}

// observe derives comparison metadata from the actual retained child. The
// original runtime issuer must independently compare its held executable,
// config/material, source and durable registration. This reader issues none.
func (p *xraySelectedTCPProcess) observe(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity) (xraySelectedTCPProcessObservation, error) {
	c, cancel, err := p.forwardContext(ctx)
	if err != nil {
		return xraySelectedTCPProcessObservation{}, err
	}
	defer cancel()
	if provider == nil || expected.Validate() != nil {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	var observed xraySelectedTCPProcessObservation
	err = provider.WithCurrent(c, func(held context.Context, current netidentity.Identity) error {
		if current != expected || p.liveCurrent(held) != nil {
			return errXraySelectedTCPRuntime
		}
		proc, err := openXraySelectedTCPProc(held, p.pid)
		if err != nil {
			return err
		}
		defer proc.close()
		before, err := p.readProcess(held, proc, current)
		if err != nil {
			return err
		}
		after, err := p.readProcess(held, proc, current)
		if err != nil || !before.same(after) || proc.current(held) != nil || p.liveCurrent(held) != nil {
			return errXraySelectedTCPRuntime
		}
		observed = after
		return nil
	})
	if err != nil || p.liveCurrent(c) != nil {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	return observed, nil
}

func (p *xraySelectedTCPProcess) readProcess(ctx context.Context, proc *xraySelectedTCPProc, network netidentity.Identity) (xraySelectedTCPProcessObservation, error) {
	if p.liveCurrent(ctx) != nil || proc == nil || proc.pid != p.pid || network.Validate() != nil {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	args := p.image.args
	ownedFD := p.image.path == "/proc/self/fd/3" && len(p.image.extras) == 2 && len(args) == 4 && args[3] == "/proc/self/fd/4"
	if len(args) != 4 || !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] || args[1] != "run" || args[2] != "-config" ||
		!ownedFD && args[3] != filepath.Join(p.image.dir, "xray-redirect.json") {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	stat, err := proc.read(ctx, proc.child, "stat", 8192)
	if err != nil {
		return xraySelectedTCPProcessObservation{}, err
	}
	start, parent, group, err := xraySelectedTCPStat(stat, p.pid)
	if err != nil || parent != p.parent {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	argv, err := proc.read(ctx, proc.child, "cmdline", 64<<10)
	if err != nil || !bytes.Equal(argv, []byte(strings.Join(args, "\x00")+"\x00")) {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	boot, err := proc.read(ctx, proc.root, "sys/kernel/random/boot_id", 37)
	if err != nil || string(boot) != network.BootID+"\n" {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	if err := proc.network(ctx, network); err != nil {
		return xraySelectedTCPProcessObservation{}, err
	}
	exe, err := proc.readlink(proc.child, "exe")
	if err != nil || !filepath.IsAbs(exe) || filepath.Clean(exe) != exe || strings.ContainsAny(exe, "\x00\r\n") || strings.HasSuffix(exe, " (deleted)") {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	fd, err := unix.Openat(proc.child, "exe", unix.O_PATH|unix.O_CLOEXEC, 0) // Follow only the kernel's actual exe magic link.
	if err != nil {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	f := os.NewFile(uintptr(fd), "[actual Xray executable]")
	executable, err := f.Stat()
	_ = f.Close()
	if err != nil || !executable.Mode().IsRegular() {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	if ownedFD {
		original, err := p.image.extras[0].Stat()
		if err != nil || !os.SameFile(original, executable) || original.Size() != executable.Size() || original.Mode() != executable.Mode() || !original.ModTime().Equal(executable.ModTime()) {
			return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
		}
	}
	config, configHash, err := p.readConfig(ctx)
	if err != nil {
		return xraySelectedTCPProcessObservation{}, err
	}
	if ownedFD {
		if err := p.readOriginalConfigFD(ctx, proc, config, configHash); err != nil {
			return xraySelectedTCPProcessObservation{}, err
		}
	}
	closing, err := proc.read(ctx, proc.child, "stat", 8192)
	closeStart, closeParent, closeGroup, parseErr := xraySelectedTCPStat(closing, p.pid)
	if err != nil || parseErr != nil || closeStart != start || closeParent != parent || closeGroup != group || proc.current(ctx) != nil || p.liveCurrent(ctx) != nil {
		return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
	}
	argumentHash := sha256.Sum256(argv)
	return xraySelectedTCPProcessObservation{pid: p.pid, parent: parent, group: group, boot: network.BootID, start: start, exe: exe,
		argumentsSHA256: hex.EncodeToString(argumentHash[:]), configSHA256: configHash, executable: executable, config: config, network: network}, nil
}

func (p *xraySelectedTCPProcess) readOriginalConfigFD(ctx context.Context, proc *xraySelectedTCPProc, named os.FileInfo, expectedHash string) error {
	if len(p.image.extras) != 2 || p.image.extras[1] == nil || proc == nil || p.liveCurrent(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	original, err := p.image.extras[1].Stat()
	if err != nil || !os.SameFile(original, named) || original.Mode() != named.Mode() || original.Size() != named.Size() || !original.ModTime().Equal(named.ModTime()) {
		return errXraySelectedTCPRuntime
	}
	directory, err := proc.open(ctx, proc.child, "fd", true)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, "4", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0) // Follow only the SAME actual child's kernel FD4 magic link.
	if err != nil {
		return errXraySelectedTCPRuntime
	}
	f := os.NewFile(uintptr(fd), "[actual original Xray config FD4]")
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(original, held) || held.Size() != original.Size() || held.Mode() != original.Mode() || !held.ModTime().Equal(original.ModTime()) {
		return errXraySelectedTCPRuntime
	}
	data, err := xraySelectedTCPReadFD(ctx, fd, 1<<20)
	defer clear(data)
	hash := sha256.Sum256(data)
	after, statErr := f.Stat()
	closing, originalErr := p.image.extras[1].Stat()
	if err != nil || statErr != nil || originalErr != nil || len(data) == 0 || int64(len(data)) != original.Size() ||
		!os.SameFile(held, after) || !os.SameFile(original, closing) || after.Size() != held.Size() || after.Mode() != held.Mode() ||
		!after.ModTime().Equal(held.ModTime()) || closing.Size() != original.Size() || !closing.ModTime().Equal(original.ModTime()) ||
		hex.EncodeToString(hash[:]) != expectedHash || proc.current(ctx) != nil || p.liveCurrent(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	return nil
}

func (p *xraySelectedTCPProcess) readConfig(ctx context.Context) (os.FileInfo, string, error) {
	if p.liveCurrent(ctx) != nil {
		return nil, "", errXraySelectedTCPRuntime
	}
	root, err := ownedfs.Open(p.image.dir)
	if err != nil {
		return nil, "", errXraySelectedTCPRuntime
	}
	defer root.Close()
	anchor, err := root.RootInfo()
	if err != nil {
		return nil, "", errXraySelectedTCPRuntime
	}
	f, err := root.OpenFile("xray-redirect.json", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", errXraySelectedTCPRuntime
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return nil, "", errXraySelectedTCPRuntime
	}
	data, err := xraySelectedTCPReadFD(ctx, int(f.Fd()), 1<<20)
	defer clear(data)
	after, statErr := f.Stat()
	named, namedErr := root.Stat("xray-redirect.json")
	directory, directoryErr := os.Lstat(p.image.dir)
	if err != nil || len(data) == 0 || statErr != nil || namedErr != nil || directoryErr != nil || !os.SameFile(before, after) || !os.SameFile(after, named) ||
		!os.SameFile(anchor, directory) || directory.Mode()&os.ModeSymlink != 0 || before.Size() != int64(len(data)) || before.Size() != after.Size() || before.Mode() != after.Mode() || after.Mode() != named.Mode() || !before.ModTime().Equal(after.ModTime()) || p.liveCurrent(ctx) != nil {
		return nil, "", errXraySelectedTCPRuntime
	}
	hash := sha256.Sum256(data)
	return after, hex.EncodeToString(hash[:]), nil
}

// Fixed procfs descriptors and mount IDs bracket the SAME original child.
// There are no caller paths/read callbacks and no missing-file waiver.
type xraySelectedTCPProc struct {
	root, child, fdinfo int
	pid                 int
	mount               uint64
	rootStat, childStat unix.Stat_t
	fs                  unix.Statfs_t
}

const xraySelectedTCPDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

func openXraySelectedTCPProc(ctx context.Context, pid int) (*xraySelectedTCPProc, error) {
	if xraySelectedTCPFinite(ctx) != nil || pid <= 1 {
		return nil, errXraySelectedTCPRuntime
	}
	r := &xraySelectedTCPProc{root: -1, child: -1, fdinfo: -1, pid: pid}
	ok := false
	defer func() {
		if !ok {
			r.close()
		}
	}()
	var err error
	r.root, err = unix.Open("/proc", xraySelectedTCPDirFlags, 0)
	if err != nil || unix.Fstat(r.root, &r.rootStat) != nil || unix.Fstatfs(r.root, &r.fs) != nil || r.rootStat.Ino != 1 || r.rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || r.fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errXraySelectedTCPRuntime
	}
	parent, err := unix.Openat(r.root, strconv.Itoa(os.Getpid()), xraySelectedTCPDirFlags, 0)
	if err != nil {
		return nil, errXraySelectedTCPRuntime
	}
	defer unix.Close(parent)
	if !r.procFile(parent, unix.S_IFDIR) {
		return nil, errXraySelectedTCPRuntime
	}
	r.fdinfo, err = unix.Openat(parent, "fdinfo", xraySelectedTCPDirFlags, 0)
	if err != nil || !r.procFile(r.fdinfo, unix.S_IFDIR) {
		return nil, errXraySelectedTCPRuntime
	}
	r.mount, err = r.mountID(ctx, r.root)
	if err != nil {
		return nil, err
	}
	for _, fd := range []int{parent, r.fdinfo} {
		if !r.sameMount(ctx, fd) {
			return nil, errXraySelectedTCPRuntime
		}
	}
	r.child, err = unix.Openat(r.root, strconv.Itoa(pid), xraySelectedTCPDirFlags, 0)
	if err != nil || !r.procFile(r.child, unix.S_IFDIR) || !r.sameMount(ctx, r.child) || unix.Fstat(r.child, &r.childStat) != nil || r.current(ctx) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	ok = true
	return r, nil
}

func (r *xraySelectedTCPProc) close() {
	for _, fd := range []int{r.child, r.fdinfo, r.root} {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}
func (r *xraySelectedTCPProc) procFile(fd int, mode uint32) bool {
	var st unix.Stat_t
	var fs unix.Statfs_t
	return fd >= 0 && unix.Fstat(fd, &st) == nil && unix.Fstatfs(fd, &fs) == nil && st.Mode&unix.S_IFMT == mode && st.Dev == r.rootStat.Dev && fs.Type == r.fs.Type && fs.Fsid == r.fs.Fsid
}
func (r *xraySelectedTCPProc) mountID(ctx context.Context, fd int) (uint64, error) {
	f, err := unix.Openat(r.fdinfo, strconv.Itoa(fd), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, errXraySelectedTCPRuntime
	}
	defer unix.Close(f)
	if !r.procFile(f, unix.S_IFREG) {
		return 0, errXraySelectedTCPRuntime
	}
	data, err := xraySelectedTCPReadFD(ctx, f, 4096)
	if err != nil || len(data) == 0 || data[len(data)-1] != '\n' {
		return 0, errXraySelectedTCPRuntime
	}
	var id uint64
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			if id != 0 {
				return 0, errXraySelectedTCPRuntime
			}
			id, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil || id == 0 || strconv.FormatUint(id, 10) != fields[1] {
				return 0, errXraySelectedTCPRuntime
			}
		}
	}
	if id == 0 {
		return 0, errXraySelectedTCPRuntime
	}
	return id, nil
}
func (r *xraySelectedTCPProc) sameMount(ctx context.Context, fd int) bool {
	id, err := r.mountID(ctx, fd)
	return err == nil && id == r.mount
}
func (r *xraySelectedTCPProc) current(ctx context.Context) error {
	if xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	var root, child, named unix.Stat_t
	if unix.Fstat(r.root, &root) != nil || unix.Fstat(r.child, &child) != nil || unix.Lstat("/proc", &named) != nil || root.Dev != r.rootStat.Dev || root.Ino != r.rootStat.Ino || root.Dev != named.Dev || root.Ino != named.Ino ||
		child.Dev != r.childStat.Dev || child.Ino != r.childStat.Ino || unix.Fstatat(r.root, strconv.Itoa(r.pid), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || child.Dev != named.Dev || child.Ino != named.Ino {
		return errXraySelectedTCPRuntime
	}
	for _, fd := range []int{r.root, r.child, r.fdinfo} {
		if !r.procFile(fd, unix.S_IFDIR) || !r.sameMount(ctx, fd) {
			return errXraySelectedTCPRuntime
		}
	}
	return nil
}
func (r *xraySelectedTCPProc) open(ctx context.Context, base int, name string, directory bool) (int, error) {
	if xraySelectedTCPFinite(ctx) != nil || !filepath.IsLocal(name) || filepath.Clean(name) != name {
		return -1, errXraySelectedTCPRuntime
	}
	parts := strings.Split(name, "/")
	current := base
	for i, part := range parts {
		flags, mode := xraySelectedTCPDirFlags, uint32(unix.S_IFDIR)
		if i == len(parts)-1 && !directory {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
			mode = unix.S_IFREG
		}
		next, err := unix.Openat(current, part, flags, 0)
		if current != base {
			_ = unix.Close(current)
		}
		if err != nil {
			return -1, errXraySelectedTCPRuntime
		}
		if !r.procFile(next, mode) || !r.sameMount(ctx, next) {
			_ = unix.Close(next)
			return -1, errXraySelectedTCPRuntime
		}
		current = next
	}
	return current, nil
}
func (r *xraySelectedTCPProc) read(ctx context.Context, base int, name string, limit int) ([]byte, error) {
	fd, err := r.open(ctx, base, name, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	data, err := xraySelectedTCPReadFD(ctx, fd, limit)
	if err != nil || !r.procFile(fd, unix.S_IFREG) || !r.sameMount(ctx, fd) {
		return nil, errXraySelectedTCPRuntime
	}
	return data, nil
}
func (r *xraySelectedTCPProc) readlink(base int, name string) (string, error) {
	var data [4097]byte
	n, err := unix.Readlinkat(base, name, data[:])
	if err != nil || n == 0 || n >= len(data) {
		return "", errXraySelectedTCPRuntime
	}
	return string(data[:n]), nil
}
func xraySelectedTCPReadFD(ctx context.Context, fd int, limit int) ([]byte, error) {
	return xraySelectedTCPReadBoundedFD(ctx, fd, limit, 8<<20)
}

func xraySelectedTCPReadBoundedFD(ctx context.Context, fd int, limit, maximum int) ([]byte, error) {
	if xraySelectedTCPFinite(ctx) != nil || maximum != 8<<20 && maximum != xraySelectedTCPConntrackLimit || limit <= 0 || limit > maximum {
		return nil, errXraySelectedTCPRuntime
	}
	var data []byte
	var block [4096]byte
	for {
		if ctx.Err() != nil {
			clear(data)
			return nil, errXraySelectedTCPRuntime
		}
		n, err := unix.Read(fd, block[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n > limit-len(data) {
			clear(data)
			return nil, errXraySelectedTCPRuntime
		}
		if n == 0 {
			return data, nil
		}
		data = append(data, block[:n]...)
	}
}
func (r *xraySelectedTCPProc) network(ctx context.Context, expected netidentity.Identity) error {
	ns, err := r.open(ctx, r.child, "ns", true)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(ns), "[actual child namespace inventory]")
	defer f.Close()
	names, err := f.Readdirnames(65)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > 64 {
		return errXraySelectedTCPRuntime
	}
	// Readdirnames(n) returns nil on a full chunk; require the next read to be
	// EOF, rather than interpreting a bounded prefix as the whole directory.
	extra, endErr := f.Readdirnames(1)
	if len(extra) != 0 || !errors.Is(endErr, io.EOF) {
		return errXraySelectedTCPRuntime
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] || !strings.Contains("|cgroup|ipc|mnt|net|pid|pid_for_children|time|time_for_children|user|uts|", "|"+name+"|") {
			return errXraySelectedTCPRuntime
		}
		seen[name] = true
	}
	if !seen["mnt"] {
		return errXraySelectedTCPRuntime
	}
	if expected.Kind == netidentity.ReviewedSingleInitNet {
		if seen["net"] {
			return errXraySelectedTCPRuntime
		}
		var raw [128]byte
		if _, err := unix.Readlinkat(ns, "net", raw[:]); !errors.Is(err, unix.ENOENT) {
			return errXraySelectedTCPRuntime
		}
		fd, err := unix.Openat(ns, "mnt", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return errXraySelectedTCPRuntime
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		var fs unix.Statfs_t
		if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino == 0 || fs.Type != unix.NSFS_MAGIC {
			return errXraySelectedTCPRuntime
		}
		return ctx.Err() // Only inside the concrete provider's reviewed stock bracket.
	}
	if expected.Kind != netidentity.ProcNetInode || !seen["net"] {
		return errXraySelectedTCPRuntime
	}
	link, err := r.readlink(ns, "net")
	if err != nil || link != "net:["+strconv.FormatUint(expected.Inode, 10)+"]" {
		return errXraySelectedTCPRuntime
	}
	fd, err := unix.Openat(ns, "net", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return errXraySelectedTCPRuntime
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino != expected.Inode || fs.Type != unix.NSFS_MAGIC {
		return errXraySelectedTCPRuntime
	}
	return ctx.Err()
}
