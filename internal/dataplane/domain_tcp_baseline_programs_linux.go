//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Native read-only BPF_PROG_QUERY on the actual effective cgroup. A local
// transparent socket must not inherit a socket/egress rewrite absent from the
// original forwarded path. cgroup-v1, denied/unsupported queries and threaded
// membership we cannot prove are explicit unsupported topology, never absence.
func domainTCPBaselinePrograms(ctx context.Context, proc *xraySelectedTCPProc) (result error) {
	if proc == nil || proc.pid != os.Getpid() || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainTCPBaselineKernel
	}
	membership, err := proc.read(ctx, proc.child, "cgroup", 16<<10)
	if err != nil {
		return err
	}
	threadName := "task/" + strconv.Itoa(unix.Gettid()) + "/cgroup"
	thread, err := proc.read(ctx, proc.child, threadName, 16<<10)
	if err != nil || !bytes.Equal(thread, membership) {
		return ErrDomainTCPBaselineKernel
	}
	text := string(membership)
	if !strings.HasPrefix(text, "0::/") || !strings.HasSuffix(text, "\n") || strings.Count(text, "\n") != 1 {
		return ErrDomainTCPBaselineKernel
	}
	name := strings.TrimSuffix(strings.TrimPrefix(text, "0::"), "\n")
	if path.Clean(name) != name || !path.IsAbs(name) || strings.ContainsAny(name, "\x00\r\\") {
		return ErrDomainTCPBaselineKernel
	}
	fd, err := unix.Open("/sys/fs/cgroup", xraySelectedTCPDirFlags, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(fd)) }()
	filesystem := func(fd int) bool {
		var st unix.Statfs_t
		return unix.Fstatfs(fd, &st) == nil && st.Type == unix.CGROUP2_SUPER_MAGIC
	}
	if !filesystem(fd) {
		return ErrDomainTCPBaselineKernel
	}
	if name != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
			next, err := unix.Openat(fd, component, xraySelectedTCPDirFlags, 0)
			if err != nil {
				return err
			}
			if !filesystem(next) {
				_ = unix.Close(next)
				return ErrDomainTCPBaselineKernel
			}
			if err := unix.Close(fd); err != nil {
				_ = unix.Close(next)
				fd = -1
				return err
			}
			fd = next
		}
	}
	// cgroupfs may be mounted at a namespace-relative subtree. Membership of
	// THIS actual process proves the opened directory is its exact group.
	checkMember := func() error {
		member, err := unix.Openat(fd, "cgroup.procs", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		if !filesystem(member) {
			_ = unix.Close(member)
			return ErrDomainTCPBaselineKernel
		}
		f := os.NewFile(uintptr(member), "original-cgroup-process-membership")
		data, err := io.ReadAll(io.LimitReader(f, 64<<10))
		closeErr := f.Close()
		if err != nil || closeErr != nil || len(data) >= 64<<10 {
			return errors.Join(ErrDomainTCPBaselineKernel, err, closeErr)
		}
		found := false
		for _, v := range strings.Fields(string(data)) {
			if v == strconv.Itoa(os.Getpid()) {
				found = true
			}
		}
		if !found {
			return ErrDomainTCPBaselineKernel
		}
		return ctx.Err()
	}
	if err := checkMember(); err != nil {
		return err
	}
	for _, attach := range []uint32{unix.BPF_CGROUP_INET_INGRESS, unix.BPF_CGROUP_INET_EGRESS, unix.BPF_CGROUP_INET_SOCK_CREATE, unix.BPF_CGROUP_SOCK_OPS, unix.BPF_CGROUP_INET4_BIND, unix.BPF_CGROUP_INET4_POST_BIND, unix.BPF_CGROUP_INET4_CONNECT, unix.BPF_CGROUP_GETSOCKOPT, unix.BPF_CGROUP_SETSOCKOPT, unix.BPF_CGROUP_INET4_GETSOCKNAME, unix.BPF_CGROUP_INET4_GETPEERNAME, unix.BPF_CGROUP_SYSCTL} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := domainTCPBaselineNoPrograms(fd, attach, unix.BPF_F_QUERY_EFFECTIVE); err != nil {
			return err
		}
	}
	if err := checkMember(); err != nil {
		return err
	}
	closing, err := proc.read(ctx, proc.child, "cgroup", 16<<10)
	closingThread, e := proc.read(ctx, proc.child, threadName, 16<<10)
	if err != nil || e != nil || !bytes.Equal(membership, closing) || !bytes.Equal(membership, closingThread) {
		return ErrDomainTCPBaselineKernel
	}
	return ctx.Err()
}

func domainTCPBaselineNoPrograms(fd int, attach, flags uint32) error {
	// Stable initial query ABI, Linux UAPI include/uapi/linux/bpf.h query.
	// No program IDs buffer is needed: the kernel always returns prog_cnt.
	attribute := struct {
		FD, Attach, Flags, AttachFlags uint32
		IDs                            uint64
		Count, Pad                     uint32
	}{FD: uint32(fd), Attach: attach, Flags: flags}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 || attribute.Count != 0 || attribute.AttachFlags != 0 {
		return errors.Join(ErrDomainTCPBaselineKernel, errno)
	}
	return nil
}
