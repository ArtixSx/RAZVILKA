//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// The exact socket inode must be a sole non-overlapping namespace listener
// AND an FD of the actual retained child, inside process/config/provider
// bookends. The original physical primary/source/COMMON witnesses remain
// separate issuer obligations; this observation grants no Ready or effects.
func (p *xraySelectedTCPProcess) observeListener(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, endpoint netip.AddrPort) (xraySelectedTCPListenerObservation, error) {
	c, cancel, err := p.forwardContext(ctx)
	if err != nil {
		return xraySelectedTCPListenerObservation{}, err
	}
	defer cancel()
	if provider == nil || expected.Validate() != nil {
		return xraySelectedTCPListenerObservation{}, errXraySelectedTCPRuntime
	}
	var observed xraySelectedTCPListenerObservation
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
		inode, err := proc.listener(held, endpoint)
		if err != nil || proc.socketFD(held, inode) != nil {
			return errXraySelectedTCPRuntime
		}
		after, err := p.readProcess(held, proc, current)
		if err != nil || !before.same(after) {
			return errXraySelectedTCPRuntime
		}
		closing, err := proc.listener(held, endpoint)
		if err != nil || closing != inode || proc.socketFD(held, inode) != nil {
			return errXraySelectedTCPRuntime
		}
		last, err := p.readProcess(held, proc, current)
		if err != nil || !after.same(last) || proc.current(held) != nil || p.liveCurrent(held) != nil {
			return errXraySelectedTCPRuntime
		}
		observed = xraySelectedTCPListenerObservation{process: last, endpoint: endpoint, inode: inode}
		return nil
	})
	if err != nil || p.liveCurrent(c) != nil {
		return xraySelectedTCPListenerObservation{}, errXraySelectedTCPRuntime
	}
	return observed, nil
}

func (r *xraySelectedTCPProc) listener(ctx context.Context, endpoint netip.AddrPort) (uint64, error) {
	v4, err := r.read(ctx, r.child, "net/tcp", 8<<20)
	if err != nil {
		return 0, err
	}
	v6, err := r.read(ctx, r.child, "net/tcp6", 8<<20)
	if err != nil {
		return 0, err
	} // Missing/inaccessible tcp6 is unknown completeness.
	rows4, err := xraySelectedTCPSockets(v4, false)
	if err != nil {
		return 0, err
	}
	rows6, err := xraySelectedTCPSockets(v6, true)
	if err != nil {
		return 0, err
	}
	return xraySelectedTCPListenerInode(rows4, rows6, endpoint)
}

func (r *xraySelectedTCPProc) socketFD(ctx context.Context, inode uint64) error {
	if inode == 0 {
		return errXraySelectedTCPRuntime
	}
	fd, err := r.open(ctx, r.child, "fd", true)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "[actual Xray FD inventory]")
	defer f.Close()
	names, err := f.Readdirnames(4097)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > 4096 {
		return errXraySelectedTCPRuntime
	}
	extra, endErr := f.Readdirnames(1)
	if len(extra) != 0 || !errors.Is(endErr, io.EOF) {
		return errXraySelectedTCPRuntime
	}
	found := false
	seen := map[string]bool{}
	for _, name := range names {
		n, err := strconv.ParseUint(name, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != name || seen[name] || ctx.Err() != nil {
			return errXraySelectedTCPRuntime
		}
		seen[name] = true
		link, err := r.readlink(fd, name)
		if err != nil {
			return err
		} // A raced-away FD cannot become negative proof.
		found = found || link == "socket:["+strconv.FormatUint(inode, 10)+"]"
	}
	if !found || !r.procFile(fd, unix.S_IFDIR) || !r.sameMount(ctx, fd) {
		return errXraySelectedTCPRuntime
	}
	return ctx.Err()
}
