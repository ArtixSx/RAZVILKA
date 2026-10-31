package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

var errNFQWSProbeSocket = errors.New("original NFQWS probe socket owner unavailable")

// Issued only inside the real Dialer.ControlContext before Connect. The held
// duplicate keeps the SAME socket/port reserved after the HTTP flow joins.
// COMMON must retain it on cleanup failure and retire it only after confirming
// both owned NFQ process and all matching rules are gone.
type nfqwsProbeSocketOwner struct {
	self      *nfqwsProbeSocketOwner
	mu        sync.Mutex
	bound     *nfqwsProbeBoundSocket
	source    *strategylab.CandidateProbeReview
	reference strategylab.CandidateProbeReference
	provider  *netidentity.Provider
	identity  netidentity.Identity
	issuer    context.Context
	closed    bool
}

func newNFQWSProbeSocketOwner(ctx context.Context, raw syscall.RawConn, source *strategylab.CandidateProbeReview, provider *netidentity.Provider) (*nfqwsProbeSocketOwner, error) {
	if ctx == nil || raw == nil || source == nil || provider == nil || ctx.Err() != nil {
		return nil, errNFQWSProbeSocket
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, errNFQWSProbeSocket
	}
	reference, err := source.Reference(ctx)
	if err != nil {
		return nil, errors.Join(errNFQWSProbeSocket, err)
	}
	if !domainPolicyTCPPublicIPv4(reference.Scope.Address) || reference.Scope.Target.Protocol != "tcp" || reference.Scope.Target.IPFamily != "ipv4" {
		return nil, errNFQWSProbeSocket
	}
	identity, err := provider.Observe(ctx)
	if err != nil {
		return nil, errors.Join(errNFQWSProbeSocket, err)
	}
	destination := netip.AddrPortFrom(reference.Scope.Address, 443)
	local, err := nfqwsProbeRouteSource(ctx, destination)
	if err != nil {
		return nil, err
	}
	bound, err := prepareNFQWSProbeBoundSocket(ctx, raw, local, destination)
	if err != nil {
		return nil, err
	}
	r := &nfqwsProbeSocketOwner{bound: bound, source: source, reference: reference, provider: provider, identity: identity, issuer: ctx}
	r.self = r
	if err := r.current(ctx); err != nil {
		_ = bound.close()
		return nil, err
	}
	return r, nil
}

func (r *nfqwsProbeSocketOwner) current(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || r.issuer == nil || r.issuer.Err() != nil {
		return errNFQWSProbeSocket
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.bound == nil || r.source == nil || r.provider == nil {
		return errNFQWSProbeSocket
	}
	reference, err := r.source.Reference(ctx)
	if err != nil || !reflect.DeepEqual(reference, r.reference) {
		return errors.Join(errNFQWSProbeSocket, err)
	}
	if err := r.provider.WithCurrent(ctx, func(_ context.Context, identity netidentity.Identity) error {
		if identity != r.identity {
			return errNFQWSProbeSocket
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.bound.current(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

// Cleanup-only private retirement; cancellation does not close the descriptor.
// A failed cleanup must retain this owner in the existing pending Execution.
func (r *nfqwsProbeSocketOwner) retire() error {
	if r == nil || r.self != r {
		return errNFQWSProbeSocket
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.bound == nil {
		return errNFQWSProbeSocket
	}
	if err := r.bound.close(); err != nil {
		return err
	}
	r.closed = true
	return nil
}
