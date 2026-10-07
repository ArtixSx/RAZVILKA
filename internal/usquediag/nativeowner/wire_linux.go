//go:build linux

package nativeowner

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type channel struct{ conn *net.UnixConn }

// A canceled forward call interrupts its socket wait without destroying the
// same retained channel needed by cleanup. Join the cancellation callback before
// another phase resets the deadline; it cannot race a subsequent cleanup call.
func (c *channel) withContext(ctx context.Context) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || c.conn.SetDeadline(deadline) != nil {
		return nil, ErrOwned
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}, nil
}

func openChannel(f *os.File, parent int, deadline time.Time) (*channel, error) {
	fd := int(f.Fd())
	unix.CloseOnExec(fd)
	typ, e1 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	cred, e2 := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if e1 != nil || e2 != nil || typ != unix.SOCK_SEQPACKET || cred.Pid != int32(parent) || cred.Uid != uint32(os.Geteuid()) {
		return nil, ErrOwned
	}
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, ErrOwned
	}
	u, ok := conn.(*net.UnixConn)
	if !ok || u.SetDeadline(deadline) != nil {
		_ = conn.Close()
		return nil, ErrOwned
	}
	return &channel{u}, nil
}
func channelPair(deadline time.Time) (*channel, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrOwned
	}
	p, c := os.NewFile(uintptr(fds[0]), "usque-owner-parent"), os.NewFile(uintptr(fds[1]), "usque-owner-helper")
	ch, err := openChannel(p, os.Getpid(), deadline)
	_ = p.Close()
	if err != nil {
		_ = c.Close()
		return nil, nil, ErrOwned
	}
	return ch, c, nil
}
func (c *channel) send(f frame) error {
	raw, err := json.Marshal(f)
	if err != nil || len(raw) > frameLimit {
		return ErrOwned
	}
	n, _, err := c.conn.WriteMsgUnix(raw, nil, nil)
	if err != nil || n != len(raw) {
		return ErrOwned
	}
	return nil
}
func (c *channel) receive() (frame, error) {
	raw := make([]byte, frameLimit+1)
	oob := make([]byte, 1)
	n, extra, flags, _, err := c.conn.ReadMsgUnix(raw, oob)
	if err != nil || n == 0 || n > frameLimit || extra != 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return frame{}, ErrOwned
	}
	return decodeFrame(raw[:n])
}
func (c *channel) close() error { return c.conn.Close() }
