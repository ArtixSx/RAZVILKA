//go:build linux

package dataplane

import (
	"context"
	"net/netip"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (r *XrayDomainTCPExecutionResource) observeDomainListener(ctx context.Context) (xraySelectedTCPListenerObservation, error) {
	if r.domainProcessCurrent(ctx) != nil || r.scope.networkIdentity == nil || r.scope.networkIdentity.provider == nil {
		return xraySelectedTCPListenerObservation{}, ErrXrayDomainTCPOriginal
	}
	var observed xraySelectedTCPListenerObservation
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
		inode, err := proc.domainListener(held, r.definition.PrivateEndpoint)
		if err != nil || proc.socketFD(held, inode) != nil {
			return ErrXrayDomainTCPOriginal
		}
		after, err := r.readDomainProcess(held, proc, current)
		if err != nil || !before.same(after) {
			return ErrXrayDomainTCPOriginal
		}
		closing, err := proc.domainListener(held, r.definition.PrivateEndpoint)
		if err != nil || closing != inode || proc.socketFD(held, inode) != nil {
			return ErrXrayDomainTCPOriginal
		}
		last, err := r.readDomainProcess(held, proc, current)
		if err != nil || !after.same(last) || proc.current(held) != nil || r.domainProcessCurrent(held) != nil {
			return ErrXrayDomainTCPOriginal
		}
		observed = xraySelectedTCPListenerObservation{process: last, endpoint: r.definition.PrivateEndpoint, inode: inode}
		return nil
	})
	if err != nil || r.domainProcessCurrent(ctx) != nil {
		return xraySelectedTCPListenerObservation{}, ErrXrayDomainTCPOriginal
	}
	return observed, nil
}

func (r *xraySelectedTCPProc) domainListener(ctx context.Context, endpoint netip.AddrPort) (uint64, error) {
	v4, err := r.read(ctx, r.child, "net/tcp", 8<<20)
	if err != nil {
		return 0, err
	}
	v6, err := r.read(ctx, r.child, "net/tcp6", 8<<20)
	if err != nil {
		return 0, err // Missing tcp6 never proves completeness.
	}
	rows4, err := xraySelectedTCPSockets(v4, false)
	if err != nil {
		return 0, err
	}
	rows6, err := xraySelectedTCPSockets(v6, true)
	if err != nil {
		return 0, err
	}
	return xrayDomainTCPListenerInode(rows4, rows6, endpoint)
}

// Actual complete parent-namespace tables under this SAME original provider.
// This private comparison does not issue a terminal or settle DNS/conntrack.
func (r *XrayDomainTCPExecutionResource) observeDomainListenerAbsent(ctx context.Context) error {
	if r == nil || r.self != r || r.scope == nil || r.scope.networkIdentity == nil || r.scope.networkIdentity.provider == nil ||
		xraySelectedTCPFinite(ctx) != nil || r.definition.NetworkIdentity.Validate() != nil {
		return ErrXrayDomainTCPOriginal
	}
	expected := r.definition.NetworkIdentity
	return r.scope.networkIdentity.provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != expected {
			return ErrXrayDomainTCPOriginal
		}
		proc, err := openXraySelectedTCPProc(held, os.Getpid())
		if err != nil {
			return err
		}
		defer proc.close()
		read := func() error {
			if proc.network(held, expected) != nil {
				return ErrXrayDomainTCPOriginal
			}
			v4, err := proc.read(held, proc.child, "net/tcp", 8<<20)
			if err != nil {
				return err
			}
			v6, err := proc.read(held, proc.child, "net/tcp6", 8<<20)
			if err != nil {
				return err
			}
			rows4, err := xraySelectedTCPSockets(v4, false)
			if err != nil {
				return err
			}
			rows6, err := xraySelectedTCPSockets(v6, true)
			if err != nil {
				return err
			}
			if xrayDomainTCPListenerAbsent(rows4, rows6, r.definition.PrivateEndpoint) != nil || proc.network(held, expected) != nil || proc.current(held) != nil {
				return ErrXrayDomainTCPOriginal
			}
			return nil
		}
		if err := read(); err != nil {
			return err
		}
		return read()
	})
}
