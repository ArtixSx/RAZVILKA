//go:build linux

package dataplane

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const nfqws2ManagedStartGrace = 3 * time.Second

type nfqws2ManagedStartSocket struct{ conn *net.UnixConn }

func nfqws2ManagedStartSocketOpen(file *os.File, parentPID int, deadline time.Time) (*nfqws2ManagedStartSocket, error) {
	if file == nil || parentPID <= 1 {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	fd := int(file.Fd())
	unix.CloseOnExec(fd) // Never pass the permission endpoint to the NFQWS child.
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	peer, credErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	local, localErr := unix.Getsockname(fd)
	remote, remoteErr := unix.Getpeername(fd)
	_, localUnix := local.(*unix.SockaddrUnix)
	_, remoteUnix := remote.(*unix.SockaddrUnix)
	if err != nil || credErr != nil || localErr != nil || remoteErr != nil || !localUnix || !remoteUnix || typ != unix.SOCK_SEQPACKET || peer.Pid != int32(parentPID) || peer.Uid != uint32(os.Geteuid()) {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	u, ok := conn.(*net.UnixConn)
	if !ok || u.SetDeadline(deadline) != nil {
		_ = conn.Close()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	return &nfqws2ManagedStartSocket{conn: u}, nil
}

func nfqws2ManagedStartSocketPair(deadline time.Time) (*nfqws2ManagedStartSocket, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	parent, child := os.NewFile(uintptr(fds[0]), "nfqws-start-parent"), os.NewFile(uintptr(fds[1]), "nfqws-start-helper")
	conn, err := nfqws2ManagedStartSocketOpen(parent, os.Getpid(), deadline)
	_ = parent.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	return conn, child, nil
}

func (s *nfqws2ManagedStartSocket) send(frame nfqws2ManagedStartFrame) error {
	data, err := json.Marshal(frame)
	if err != nil || len(data) == 0 || len(data) > nfqws2ManagedStartFrameLimit {
		return ErrNFQWSManagedProcessUnknown
	}
	n, _, err := s.conn.WriteMsgUnix(data, nil, nil)
	if err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if n != len(data) {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}

func (s *nfqws2ManagedStartSocket) receive() (nfqws2ManagedStartFrame, error) {
	data := make([]byte, nfqws2ManagedStartFrameLimit+1)
	oob := make([]byte, 1)
	n, oobn, flags, _, err := s.conn.ReadMsgUnix(data, oob)
	if err != nil {
		return nfqws2ManagedStartFrame{}, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if n == 0 || n > nfqws2ManagedStartFrameLimit || oobn != 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return nfqws2ManagedStartFrame{}, ErrNFQWSManagedProcessUnknown
	}
	return nfqws2ManagedStartDecode(data[:n])
}

func (s *nfqws2ManagedStartSocket) close() error { return s.conn.Close() }
