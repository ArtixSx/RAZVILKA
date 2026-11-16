//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type linuxInactiveProcPass struct {
	self                                            *linuxInactiveProcPass
	ctx                                             context.Context
	root, selfDir, namespace, nsDir, nsLink, fdinfo int
	pid                                             int
	rootImage, selfImage, namespaceImage            unix.Stat_t
	rootFS                                          unix.Statfs_t
	rootMount, selfTicks                            string
	children                                        int
	closed                                          bool
}

type linuxInactiveProcPID struct {
	self                                 *linuxInactiveProcPID
	pass                                 *linuxInactiveProcPass
	owner                                *linuxInactiveProcPass
	fd, pid                              int
	image                                unix.Stat_t
	ticks                                string
	observedState                        byte
	observedThreads                      int
	terminalGone, terminalZombie, closed bool
}

func inactiveProcSame(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

func openLinuxInactiveProc(ctx context.Context, root string, selfPID int) (inactiveProcPass, error) {
	if ctx == nil || ctx.Err() != nil || root != "/proc" || selfPID != os.Getpid() || selfPID < 1 {
		return nil, ErrProxyRuntimeInactive
	}
	p := &linuxInactiveProcPass{ctx: ctx, root: -1, selfDir: -1, namespace: -1, nsDir: -1, nsLink: -1, fdinfo: -1, pid: selfPID}
	p.self = p
	var err error
	p.root, err = unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		err = unix.Fstat(p.root, &p.rootImage)
	}
	if err == nil {
		err = unix.Fstatfs(p.root, &p.rootFS)
	}
	if err == nil && (p.rootImage.Ino != 1 || p.rootImage.Mode&unix.S_IFMT != unix.S_IFDIR || p.rootFS.Type != unix.PROC_SUPER_MAGIC) {
		err = ErrProxyRuntimeInactive
	}
	if err == nil {
		p.selfDir, err = unix.Openat(p.root, strconv.Itoa(selfPID), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		err = unix.Fstat(p.selfDir, &p.selfImage)
	}
	if err == nil {
		p.fdinfo, err = unix.Openat(p.selfDir, "fdinfo", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		p.nsDir, err = unix.Openat(p.selfDir, "ns", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		p.rootMount, err = p.mountID(p.root)
	}
	if err == nil {
		for _, fd := range []int{p.root, p.selfDir, p.fdinfo, p.nsDir} {
			if err = p.checkFD(fd, unix.S_IFDIR); err != nil {
				break
			}
		}
	}
	if err == nil {
		p.nsLink, err = unix.Openat(p.nsDir, "pid", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		err = p.checkFD(p.nsLink, unix.S_IFLNK)
	}
	if err == nil {
		p.namespace, err = unix.Openat(p.nsDir, "pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		err = unix.Fstat(p.namespace, &p.namespaceImage)
	}
	if err == nil {
		var fs unix.Statfs_t
		err = unix.Fstatfs(p.namespace, &fs)
		if err == nil && fs.Type != unix.NSFS_MAGIC {
			err = ErrProxyRuntimeInactive
		}
	}
	if err == nil {
		p.selfTicks, err = p.readSelfTicks()
	}
	if err == nil {
		err = p.currentRoot()
	}
	if err != nil {
		return nil, errors.Join(ErrProxyRuntimeInactive, err, p.closeFDs())
	}
	return p, nil
}

func inactiveProcLink(fd int, name string) (string, error) {
	var buf [4097]byte
	n, err := unix.Readlinkat(fd, name, buf[:])
	if err != nil {
		return "", err
	}
	if n < 1 || n > 4096 {
		return "", ErrProxyRuntimeInactive
	}
	return string(buf[:n]), nil
}

func (p *linuxInactiveProcPass) valid() error {
	if p == nil || p.self != p || p.closed || p.root < 0 || p.ctx == nil {
		return ErrProxyRuntimeInactive
	}
	return p.ctx.Err()
}

func (p *linuxInactiveProcPass) basicFD(fd int, kind uint32) error {
	if err := p.valid(); err != nil {
		return err
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != kind || st.Dev != p.rootImage.Dev || fs.Type != unix.PROC_SUPER_MAGIC || fs.Fsid != p.rootFS.Fsid {
		return ErrProxyRuntimeInactive
	}
	return p.ctx.Err()
}

// Linux 4.9-compatible fallback: the original fresh protected fdinfo query.
func (p *linuxInactiveProcPass) mountIDFromFDInfo(fd int) (string, error) {
	if err := p.basicFD(p.fdinfo, unix.S_IFDIR); err != nil {
		return "", err
	}
	return p.readMountIDFromFDInfo(fd)
}

// Called only after the current invocation validated fdinfo custody.
func (p *linuxInactiveProcPass) readMountIDFromFDInfo(fd int) (string, error) {
	leaf, err := unix.Openat(p.fdinfo, strconv.Itoa(fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	if err := p.basicFD(leaf, unix.S_IFREG); err != nil {
		return "", errors.Join(err, unix.Close(leaf))
	}
	raw, readErr := backendInventoryReadProcFD(p.ctx, leaf, 4096)
	closeErr := errors.Join(p.basicFD(leaf, unix.S_IFREG), unix.Close(leaf))
	if readErr != nil || closeErr != nil {
		return "", errors.Join(readErr, closeErr)
	}
	return backendInventoryProcMountID(raw)
}

func (p *linuxInactiveProcPass) checkFD(fd int, kind uint32) error {
	if err := p.basicFD(fd, kind); err != nil {
		return err
	}
	id, err := p.mountID(fd)
	if err != nil || p.rootMount == "" || id != p.rootMount {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	return p.ctx.Err()
}

func (p *linuxInactiveProcPass) namedFD(parent int, name string, held int, kind uint32) error {
	fd, err := unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var original, named unix.Stat_t
	err = errors.Join(unix.Fstat(held, &original), unix.Fstat(fd, &named), p.checkFD(fd, kind), unix.Close(fd))
	if err != nil || !inactiveProcSame(original, named) {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	return p.ctx.Err()
}
func (p *linuxInactiveProcPass) namedDirectory(parent int, name string, held int) error {
	return p.namedFD(parent, name, held, unix.S_IFDIR)
}
func (p *linuxInactiveProcPass) namedLink(parent int, name string, held int) error {
	return p.namedFD(parent, name, held, unix.S_IFLNK)
}

func (p *linuxInactiveProcPass) readSelfTicks() (string, error) {
	fd, err := unix.Openat(p.selfDir, "stat", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	if err := p.checkFD(fd, unix.S_IFREG); err != nil {
		return "", errors.Join(err, unix.Close(fd))
	}
	raw, readErr := backendInventoryReadProcFD(p.ctx, fd, 16<<10)
	closeErr := errors.Join(p.checkFD(fd, unix.S_IFREG), p.namedFD(p.selfDir, "stat", fd, unix.S_IFREG), unix.Close(fd))
	if readErr != nil || closeErr != nil {
		return "", errors.Join(readErr, closeErr)
	}
	state, ticks, _, err := inactiveProcThreads(raw, p.pid)
	clear(raw)
	if err != nil || state == 'Z' || state == 'X' || state == 'x' {
		return "", errors.Join(ErrProxyRuntimeInactive, err)
	}
	return ticks, p.ctx.Err()
}

func (p *linuxInactiveProcPass) currentRoot() error {
	if err := p.valid(); err != nil {
		return err
	}
	var fs unix.Statfs_t
	var held, named, self, ns unix.Stat_t
	if err := unix.Fstatfs(p.root, &fs); err != nil {
		return err
	}
	if fs.Type != unix.PROC_SUPER_MAGIC || fs.Fsid != p.rootFS.Fsid {
		return ErrProxyRuntimeInactive
	}
	if err := unix.Fstat(p.root, &held); err != nil {
		return err
	}
	if err := unix.Lstat("/proc", &named); err != nil {
		return err
	}
	if !inactiveProcSame(held, p.rootImage) || !inactiveProcSame(named, p.rootImage) {
		return ErrProxyRuntimeInactive
	}
	link, err := inactiveProcLink(p.root, "self")
	if err != nil || link != strconv.Itoa(p.pid) {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	if err := unix.Fstatat(p.root, link, &self, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !inactiveProcSame(self, p.selfImage) {
		return ErrProxyRuntimeInactive
	}
	for _, fd := range []int{p.root, p.selfDir, p.fdinfo, p.nsDir} {
		if err := p.checkFD(fd, unix.S_IFDIR); err != nil {
			return err
		}
	}
	// Reopen the complete named chain; fstatat alone cannot distinguish a bind
	// mount of the same inode. Every temporary descriptor closes on every path.
	if err := p.namedDirectory(p.root, strconv.Itoa(p.pid), p.selfDir); err != nil {
		return err
	}
	if err := p.namedDirectory(p.selfDir, "fdinfo", p.fdinfo); err != nil {
		return err
	}
	if err := p.namedDirectory(p.selfDir, "ns", p.nsDir); err != nil {
		return err
	}
	if err := p.checkFD(p.nsLink, unix.S_IFLNK); err != nil {
		return err
	}
	if err := p.namedLink(p.nsDir, "pid", p.nsLink); err != nil {
		return err
	}
	rootFD, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = errors.Join(p.checkFD(rootFD, unix.S_IFDIR), unix.Close(rootFD))
	if err != nil {
		return err
	}
	ticks, err := p.readSelfTicks()
	if err != nil || ticks != p.selfTicks {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	fd, err := unix.Openat(p.nsDir, "pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var namespaceFS unix.Statfs_t
	err = errors.Join(unix.Fstat(fd, &ns), unix.Fstatfs(fd, &namespaceFS), p.namedLink(p.nsDir, "pid", p.nsLink), unix.Close(fd))
	if err != nil || namespaceFS.Type != unix.NSFS_MAGIC || !inactiveProcSame(ns, p.namespaceImage) {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	return p.ctx.Err()
}

func (p *linuxInactiveProcPass) Entries() ([]os.DirEntry, error) {
	if err := p.valid(); err != nil {
		return nil, err
	}
	// The duplicate owns its Go wrapper; the retained root stays open until the
	// complete process/socket pass and every PID handle have closed.
	fd, err := unix.FcntlInt(uintptr(p.root), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "inactive-proc-root")
	entries, readErr := f.ReadDir(8193)
	closeErr := f.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if readErr != nil || closeErr != nil || len(entries) == 0 || len(entries) > 8192 {
		return nil, errors.Join(ErrProxyRuntimeInactive, readErr, closeErr)
	}
	return entries, p.ctx.Err()
}

func (p *linuxInactiveProcPass) OpenPID(pid int) (inactiveProcPID, error) {
	if err := p.valid(); err != nil {
		return nil, err
	}
	if pid < 1 {
		return nil, ErrProxyRuntimeInactive
	}
	fd, err := unix.Openat(p.root, strconv.Itoa(pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	h := &linuxInactiveProcPID{pass: p, owner: p, fd: fd, pid: pid}
	h.self = h
	if err := unix.Fstat(fd, &h.image); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	if err := p.checkFD(fd, unix.S_IFDIR); err != nil {
		return nil, errors.Join(ErrProxyRuntimeInactive, err, unix.Close(fd))
	}
	p.children++
	if err := h.Current(); err != nil {
		return nil, errors.Join(err, h.Close())
	}
	return h, nil
}

func (p *linuxInactiveProcPass) GoneBeforeOpen(pid int) bool {
	if p.valid() != nil || pid < 1 || pid == p.pid {
		return false
	}
	var named unix.Stat_t
	return errors.Is(unix.Fstatat(p.root, strconv.Itoa(pid), &named, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) && p.ctx.Err() == nil
}

func (p *linuxInactiveProcPass) closeFDs() (result error) {
	for _, fd := range []int{p.namespace, p.nsLink, p.nsDir, p.fdinfo, p.selfDir, p.root} {
		if fd >= 0 {
			result = errors.Join(result, unix.Close(fd))
		}
	}
	p.namespace, p.nsLink, p.nsDir, p.fdinfo, p.selfDir, p.root = -1, -1, -1, -1, -1, -1
	p.closed = true
	return result
}

func (p *linuxInactiveProcPass) Close() error {
	if p == nil || p.self != p || p.closed {
		return ErrProxyRuntimeInactive
	}
	err := p.currentRoot()
	if p.children != 0 {
		err = errors.Join(err, ErrProxyRuntimeInactive)
	}
	return errors.Join(err, p.closeFDs())
}

func (h *linuxInactiveProcPID) valid() error {
	if h == nil || h.self != h || h.closed || h.fd < 0 || h.pass == nil || h.owner != h.pass {
		return ErrProxyRuntimeInactive
	}
	return h.pass.valid()
}

func (h *linuxInactiveProcPID) Current() error {
	if err := h.valid(); err != nil {
		return err
	}
	var held, named unix.Stat_t
	if err := unix.Fstat(h.fd, &held); err != nil {
		return err
	}
	if !inactiveProcSame(held, h.image) {
		return ErrProxyRuntimeInactive
	}
	if err := h.pass.checkFD(h.fd, unix.S_IFDIR); err != nil {
		return err
	}
	err := unix.Fstatat(h.pass.root, strconv.Itoa(h.pid), &named, unix.AT_SYMLINK_NOFOLLOW)
	if h.terminalGone {
		if errors.Is(err, unix.ENOENT) {
			return h.pass.ctx.Err()
		}
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	if err != nil || !inactiveProcSame(named, h.image) {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	if err := h.pass.namedDirectory(h.pass.root, strconv.Itoa(h.pid), h.fd); err != nil {
		return err
	}
	return h.pass.ctx.Err()
}

func (h *linuxInactiveProcPID) read(name string, limit int64) ([]byte, error) {
	if err := h.valid(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(h.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := h.pass.checkFD(fd, unix.S_IFREG); err != nil {
		return nil, errors.Join(ErrProxyRuntimeInactive, err, unix.Close(fd))
	}
	data, readErr := backendInventoryReadProcFD(h.pass.ctx, fd, int(limit))
	closeErr := errors.Join(h.pass.checkFD(fd, unix.S_IFREG), h.pass.namedFD(h.fd, name, fd, unix.S_IFREG), unix.Close(fd))
	if readErr != nil || closeErr != nil || int64(len(data)) > limit || h.pass.ctx.Err() != nil {
		clear(data)
		return nil, errors.Join(ErrProxyRuntimeInactive, readErr, closeErr, h.pass.ctx.Err())
	}
	return data, nil
}

func (h *linuxInactiveProcPID) Stat() ([]byte, error) {
	raw, err := h.read("stat", 16<<10)
	if err != nil {
		return nil, err
	}
	state, ticks, threads, err := inactiveProcThreads(raw, h.pid)
	if err != nil || h.ticks != "" && h.ticks != ticks {
		clear(raw)
		return nil, &inactiveProcStatFailure{birth: err == nil}
	}
	if err := h.Current(); err != nil {
		clear(raw)
		return nil, err
	}
	if h.ticks == "" {
		h.ticks = ticks
	}
	h.observedState, h.observedThreads = state, threads
	return raw, nil
}

func (h *linuxInactiveProcPID) Command() ([]byte, error) {
	if err := h.Current(); err != nil {
		return nil, err
	}
	if h.ticks == "" {
		return nil, ErrProxyRuntimeInactive
	}
	raw, err := h.read("cmdline", 64<<10)
	err = errors.Join(err, h.Current())
	if err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}

func (h *linuxInactiveProcPID) Executable() (string, error) {
	if err := h.Current(); err != nil {
		return "", err
	}
	if h.ticks == "" {
		return "", ErrProxyRuntimeInactive
	}
	fd, err := unix.Openat(h.fd, "exe", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	if err := h.pass.checkFD(fd, unix.S_IFLNK); err != nil {
		return "", errors.Join(ErrProxyRuntimeInactive, err, unix.Close(fd))
	}
	value, err := inactiveProcLink(fd, "")
	err = errors.Join(err, h.pass.checkFD(fd, unix.S_IFLNK), h.pass.namedLink(h.fd, "exe", fd), h.Current(), unix.Close(fd))
	return value, err
}

func (h *linuxInactiveProcPID) Terminal() bool {
	if h.valid() != nil || h.pid == h.pass.pid {
		return false
	}
	if h.observedState == 'X' || h.observedState == 'x' || h.observedState == 'Z' && h.observedThreads != 1 {
		return false
	}
	for sample := 0; sample < 2; sample++ {
		raw, err := h.read("stat", 16<<10)
		if inactiveProcRetireError(err) {
			if !h.pass.GoneBeforeOpen(h.pid) {
				return false
			}
			h.terminalGone = true
			return h.Current() == nil
		}
		if err != nil {
			return false
		}
		state, ticks, threads, err := inactiveProcThreads(raw, h.pid)
		clear(raw)
		if err != nil || h.ticks == "" || ticks != h.ticks || state != 'Z' || threads != 1 || h.Current() != nil {
			return false
		}
	}
	h.terminalZombie = true
	return h.Current() == nil
}

func (h *linuxInactiveProcPID) Close() error {
	if h == nil || h.self != h || h.closed || h.fd < 0 || h.pass == nil || h.owner != h.pass || h.pass.self != h.pass {
		return ErrProxyRuntimeInactive
	}
	err := h.Current()
	if (h.observedState == 'Z' || h.observedState == 'X' || h.observedState == 'x') && !h.terminalZombie && !h.terminalGone {
		err = errors.Join(err, ErrProxyRuntimeInactive)
	}
	if h.terminalZombie && err == nil {
		raw, readErr := h.read("stat", 16<<10)
		state, ticks, threads, parseErr := inactiveProcThreads(raw, h.pid)
		clear(raw)
		if readErr != nil || parseErr != nil || state != 'Z' || threads != 1 || ticks != h.ticks {
			err = errors.Join(ErrProxyRuntimeInactive, readErr, parseErr)
		}
		err = errors.Join(err, h.Current())
	}
	fd := h.fd
	h.fd = -1
	h.closed = true
	h.pass.children--
	return errors.Join(err, unix.Close(fd))
}
