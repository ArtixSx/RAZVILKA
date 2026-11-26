//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// Exactly one ordinary IPv4 on the original egress is the initial supported
// subset. Multiple addresses, a renamed/replaced link or the client's address
// are not guessed from a preferred route. The original provider anchors netns.
func (d *domainTCPDirectScope) sourceCurrentHeld() (netip.Addr, error) {
	iface, err := net.InterfaceByName(d.path.Egress)
	if err != nil || iface.Index != d.path.EgressIndex || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return netip.Addr{}, errors.Join(ErrDomainTCPBaselineKernel, err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	var source netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return netip.Addr{}, ErrDomainTCPBaselineKernel
		}
		ip := prefix.Addr()
		if !ip.Is4() {
			continue
		}
		if source.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip == d.accepted.socket.Source.Addr() || ip == d.target.Addr() {
			return netip.Addr{}, ErrDomainTCPBaselineKernel
		}
		source = ip
	}
	if !source.IsValid() || d.source.IsValid() && source != d.source {
		return netip.Addr{}, ErrDomainTCPBaselineKernel
	}
	return source, nil
}

func (d *domainTCPDirectScope) sourceCurrent(ctx context.Context) error {
	s := d.kernel.capture.process.scope
	return s.networkIdentity.provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
		if identity != s.networkIdentity.value {
			return ErrDomainTCPBaselineKernel
		}
		_, err := d.sourceCurrentHeld()
		return errors.Join(err, held.Err())
	})
}

func (d *domainTCPDirectScope) localRoute(ctx context.Context) (result error) {
	finish := domainTCPMeasureAcceptedStage(ctx, "direct-local-route")
	defer func() { finish(result) }()
	reader, ok := d.kernel.reader.(domainTCPDirectRouteReader)
	if !ok {
		return ErrDomainTCPBaselineKernel
	}
	if err := d.sourceCurrent(ctx); err != nil {
		return err
	}
	read, err := reader.ReadDomainTCPDirectRoute(ctx, d.source, d.target.Addr())
	if err != nil {
		return err
	}
	if err := domainTCPDirectRouteReadMatches(read, d.source, d.target, d.path); err != nil {
		return err
	}
	err = d.sourceCurrent(ctx)
	return errors.Join(err, ctx.Err())
}

func (d *domainTCPDirectScope) connect(ctx context.Context) (net.Conn, error) {
	s := d.kernel.capture.process.scope
	var file, accepted *os.File
	var conn *net.TCPConn
	fd := -1
	var localPort uint16
	closeOwned := func() error {
		var result error
		if conn != nil {
			result = errors.Join(result, conn.Close())
		}
		if file != nil {
			result = errors.Join(result, file.Close())
		}
		if accepted != nil {
			result = errors.Join(result, accepted.Close())
		}
		return result
	}
	err := s.networkIdentity.provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
		if identity != s.networkIdentity.value {
			return ErrDomainTCPBaselineKernel
		}
		if err := d.registered(held); err != nil {
			return err
		}
		var err error
		d.source, err = d.sourceCurrentHeld()
		if err != nil {
			return err
		}
		raw, err := d.accepted.conn.SyscallConn()
		if err != nil {
			return err
		}
		var duplicate int
		var duplicateErr error
		if err := raw.Control(func(in uintptr) { duplicate, duplicateErr = unix.FcntlInt(in, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
			return err
		}
		if duplicateErr != nil {
			return duplicateErr
		}
		accepted = os.NewFile(uintptr(duplicate), "original-router-direct-accepted")
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		file = os.NewFile(uintptr(fd), "original-router-direct-outbound")
		// Unlike the historical transparent path, this normal socket has no
		// client source, mark, transparent option or per-flow packet effects.
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, d.path.Egress); err != nil {
			return err
		}
		if err := unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0}); err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: d.source.As4(), Port: 0}); err != nil {
			return err
		}
		address, err := unix.Getsockname(fd)
		if err != nil {
			return err
		}
		local, ok := address.(*unix.SockaddrInet4)
		if !ok || local.Port <= 0 || local.Addr != d.source.As4() {
			return ErrDomainTCPBaselineKernel
		}
		localPort = uint16(local.Port)
		return held.Err()
	})
	// Full CLI/kernel observations and waiting must not consume the short
	// provider callback budget. Each namespace-sensitive leaf retains its own
	// original provider opening/closing; the caller deadline never changes.
	if err == nil {
		err = d.localRoute(ctx)
	}
	if err == nil {
		finish := domainTCPMeasureAcceptedStage(ctx, "direct-current-pre")
		err = d.current(ctx)
		finish(err)
	}
	if err == nil {
		err = s.networkIdentity.provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
			if identity != s.networkIdentity.value {
				return ErrDomainTCPBaselineKernel
			}
			if _, err := d.sourceCurrentHeld(); err != nil {
				return err
			}
			s.startMu.RLock()
			return func() error {
				defer s.startMu.RUnlock()
				if err := d.registered(held); err != nil {
					return err
				}
				return d.kernel.capture.process.material.control.WithStart(held, func() error {
					flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
					if err != nil || flags&unix.O_NONBLOCK == 0 {
						return errors.Join(ErrDomainTCPBaselineKernel, err)
					}
					err = unix.Connect(fd, &unix.SockaddrInet4{Addr: d.target.Addr().As4(), Port: int(d.target.Port())})
					if errors.Is(err, unix.EINPROGRESS) {
						return nil
					}
					return err
				})
			}()
		})
	}
	if err == nil {
		finish := domainTCPMeasureAcceptedStage(ctx, "direct-connect-wait")
		err = domainTCPBaselineWaitConnect(ctx, fd)
		finish(err)
	}
	if err == nil {
		err = s.networkIdentity.provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
			if identity != s.networkIdentity.value {
				return ErrDomainTCPBaselineKernel
			}
			copied, err := net.FileConn(file)
			if err != nil {
				return err
			}
			var ok bool
			conn, ok = copied.(*net.TCPConn)
			if !ok {
				return errors.Join(ErrDomainTCPBaselineKernel, copied.Close())
			}
			if conn.LocalAddr().(*net.TCPAddr).AddrPort() != netip.AddrPortFrom(d.source, localPort) || conn.RemoteAddr().(*net.TCPAddr).AddrPort() != d.target {
				return ErrDomainTCPBaselineKernel
			}
			return d.registered(held)
		})
	}
	if err == nil {
		err = d.localRoute(ctx)
	}
	if err == nil {
		finish := domainTCPMeasureAcceptedStage(ctx, "direct-current-post")
		err = d.current(ctx)
		finish(err)
	}
	if err != nil || ctx.Err() != nil {
		closeErr := closeOwned()
		d.kernel.capture.capture.recordDirectFailure(closeErr)
		return nil, errors.Join(err, ctx.Err(), closeErr)
	}
	c := &domainTCPDirectConn{conn: conn, capture: d.kernel.capture.capture, ctx: ctx, closeOwned: closeOwned, callbackDone: make(chan struct{})}
	c.self = c
	c.stop = context.AfterFunc(ctx, func() { defer close(c.callbackDone); c.closeLocal() })
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), c.Close())
	}
	return c, nil
}
