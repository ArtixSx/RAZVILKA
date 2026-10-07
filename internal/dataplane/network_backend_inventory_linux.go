//go:build linux

package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

func backendInventorySystemPlatform(provider *netidentity.Provider) backendInventoryPlatform {
	return backendInventoryPlatform{withCurrent: provider.WithCurrent, registeredTables: backendInventoryRegisteredTables, openNFT: openBackendNFTSocket}
}

type backendNFTSocket struct {
	fd             int
	port, sequence uint32
	budget         backendNFTBudget
	closed         bool
	failed         bool
	abi            backendNFTABI
}

// GET can trigger kernel request_module on some kernels. This is an observer
// with no explicit module/batch/mutation probe, not a claim of zero autoload.
func openBackendNFTSocket(ctx context.Context) (backendNFTSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	seq := binary.NativeEndian.Uint32(seed[:])
	if seq == 0 || seq > ^uint32(0)-3 {
		seq = 1
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Family != unix.AF_NETLINK || local.Pid == 0 || local.Groups != 0 {
		return nil, errBackendInventory
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failed = false
	return &backendNFTSocket{fd: fd, port: local.Pid, sequence: seq}, nil
}

func (s *backendNFTSocket) Generation(ctx context.Context) (uint32, error) {
	d, err := s.exchange(ctx, backendNFTGetGen, 0, backendNFTABI49)
	if err != nil {
		return 0, err
	}
	return d.generation, nil
}

func (s *backendNFTSocket) Registration(ctx context.Context, abi backendNFTABI) (backendNFTRegistration, error) {
	if !abi.inventoryABI() {
		return backendNFTRegistration{}, errBackendInventory
	}
	d, err := s.exchange(ctx, backendNFTGetGen, 0, abi)
	if err != nil {
		return backendNFTRegistration{}, err
	}
	return d.registration()
}

func (s *backendNFTSocket) Tables(ctx context.Context, generation uint32) ([]backendNFTTable, error) {
	abi := backendNFTABI49
	if s != nil && s.abi != 0 {
		abi = s.abi
	}
	d, err := s.exchange(ctx, backendNFTGetTable, generation, abi)
	if err != nil {
		return nil, err
	}
	return append([]backendNFTTable(nil), d.tables...), nil
}

func (s *backendNFTSocket) Close() error {
	if s == nil || s.closed {
		return errBackendInventory
	}
	s.closed = true
	return unix.Close(s.fd)
}

func (s *backendNFTSocket) exchange(ctx context.Context, kind uint16, generation uint32, abi backendNFTABI) (result *backendNFTDecoder, resultErr error) {
	defer func() {
		if s != nil && resultErr != nil {
			s.failed = true
		}
	}()
	if ctx == nil || s == nil || s.closed || s.failed || ctx.Err() != nil || s.abi != 0 && s.abi != abi {
		return nil, errBackendInventory
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > backendInventoryTimeout {
		return nil, errBackendInventory
	}
	request, err := backendNFTRequest(kind, s.sequence, s.port)
	if err != nil {
		return nil, err
	}
	s.sequence++
	d, err := newBackendNFTDecoderABI(request, generation, &s.budget, abi)
	if err != nil {
		return nil, err
	}
	s.abi = abi
	buffer := make([]byte, backendNFTMaxDatagram)
	if _, queued, err := s.receive(buffer); err != nil || queued {
		return nil, errors.Join(errBackendInventory, err)
	}
	// NONBLOCK does not preempt synchronous kernel handlers/request_module.
	// The context bounds userspace receive/poll, not a stuck kernel syscall.
	if err := unix.Sendto(s.fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	for !d.done {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		wait := min(20, int((remaining+time.Millisecond-1)/time.Millisecond))
		poll := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents != unix.POLLIN {
			return nil, errBackendInventory
		}
		packet, received, err := s.receive(buffer)
		if err != nil {
			return nil, err
		}
		if !received {
			continue
		}
		if err := d.consume(packet); err != nil {
			return nil, err
		}
	}
	if err := errors.Join(ctx.Err(), d.closeReceive(func() (backendNFTDatagram, bool, error) { return s.receive(buffer) })); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *backendNFTSocket) receive(buffer []byte) (backendNFTDatagram, bool, error) {
	n, _, flags, sender, err := unix.Recvmsg(s.fd, buffer, nil, unix.MSG_DONTWAIT)
	if errors.Is(err, unix.EAGAIN) {
		return backendNFTDatagram{}, false, nil
	}
	if err != nil {
		return backendNFTDatagram{}, false, err
	}
	peer, ok := sender.(*unix.SockaddrNetlink)
	if !ok || peer.Family != unix.AF_NETLINK || n <= 0 || n > len(buffer) || flags&^(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return backendNFTDatagram{}, true, errBackendInventory
	}
	return backendNFTDatagram{Data: buffer[:n], SenderPID: peer.Pid, Groups: peer.Groups, Truncated: flags&unix.MSG_TRUNC != 0, ControlTruncated: flags&unix.MSG_CTRUNC != 0}, true, nil
}

// Within Provider.WithCurrent: walk the actual PID/task/TID net directory,
// never /proc/net's process symlink. No symlink or different proc mount is
// accepted. Empty EOF is valid; missing/unreadable names are Unknown.
func backendInventoryRegisteredTables(ctx context.Context, family int) (result []byte, resultErr error) {
	if ctx == nil || ctx.Err() != nil || family != 4 && family != 6 {
		return nil, errBackendInventory
	}
	pid, tid := unix.Getpid(), unix.Gettid()
	const dirs = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	root, err := unix.Open("/proc", dirs, 0)
	if err != nil {
		return nil, err
	}
	fds := []int{root}
	defer func() {
		var closing error
		for i := len(fds) - 1; i >= 0; i-- {
			closing = errors.Join(closing, unix.Close(fds[i]))
		}
		if closing != nil {
			result = nil
			resultErr = errors.Join(errBackendInventory, resultErr, closing)
		}
	}()
	var rootStat unix.Stat_t
	var rootFS unix.Statfs_t
	if unix.Fstat(root, &rootStat) != nil || unix.Fstatfs(root, &rootFS) != nil || rootStat.Ino != 1 || rootFS.Type != unix.PROC_SUPER_MAGIC || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errBackendInventory
	}
	check := func(fd int, directory bool) bool {
		var st unix.Stat_t
		var fs unix.Statfs_t
		want := uint32(unix.S_IFREG)
		if directory {
			want = unix.S_IFDIR
		}
		return unix.Fstat(fd, &st) == nil && unix.Fstatfs(fd, &fs) == nil && st.Mode&unix.S_IFMT == want && st.Dev == rootStat.Dev && fs.Type == rootFS.Type && fs.Fsid == rootFS.Fsid
	}
	parent := root
	var pidFD int
	for i, part := range []string{strconv.Itoa(pid), "task", strconv.Itoa(tid), "net"} {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fd, err := unix.Openat(parent, part, dirs, 0)
		if err != nil {
			return nil, err
		}
		fds = append(fds, fd)
		if !check(fd, true) {
			return nil, errBackendInventory
		}
		if i == 0 {
			pidFD = fd
		}
		parent = fd
	}
	name := "ip_tables_names"
	if family == 6 {
		name = "ip6_tables_names"
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fds = append(fds, fd)
	if !check(fd, false) {
		return nil, errBackendInventory
	}
	info, err := unix.Openat(pidFD, "fdinfo", dirs, 0)
	if err != nil {
		return nil, err
	}
	fds = append(fds, info)
	if !check(info, true) {
		return nil, errBackendInventory
	}
	mount := func(descriptor int) (string, error) {
		f, err := unix.Openat(info, strconv.Itoa(descriptor), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return "", err
		}
		file := os.NewFile(uintptr(f), "proc-fdinfo")
		if file == nil {
			_ = unix.Close(f)
			return "", errBackendInventory
		}
		if !check(f, false) {
			_ = file.Close()
			return "", errBackendInventory
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 4096 {
			return "", errBackendInventory
		}
		return backendInventoryProcMountID(data)
	}
	rootMount, err := mount(root)
	if err != nil {
		return nil, err
	}
	for _, f := range fds {
		if got, err := mount(f); err != nil || got != rootMount {
			return nil, errBackendInventory
		}
	}
	// Duplicate ownership for os.File; retained FD is used for closing checks.
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(dup), "classic-table-names")
	data, readErr := io.ReadAll(io.LimitReader(file, backendClassicNamesBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > backendClassicNamesBytes || ctx.Err() != nil || unix.Getpid() != pid || unix.Gettid() != tid {
		return nil, errors.Join(errBackendInventory, readErr, closeErr, ctx.Err())
	}
	for i, f := range fds {
		if !check(f, i != len(fds)-2) {
			return nil, errBackendInventory
		}
		if got, err := mount(f); err != nil || got != rootMount {
			return nil, errBackendInventory
		}
	}
	return data, nil
}
