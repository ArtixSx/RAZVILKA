package dataplane

import (
	"context"
	"sync/atomic"
)

// This domain-only interval has no issuer yet. The original scope publisher
// must first check its actual typed map, both authored journal FDs and its
// fresh operation/cleanup owner before opening an interval under resource.mu.
// A literal selected-TCP read interval is deliberately insufficient here.
type xrayDomainTCPProcessReadKey struct{}
type xrayDomainTCPProcessRead struct {
	self     *xrayDomainTCPProcessRead
	resource *XrayDomainTCPExecutionResource
	process  *xraySelectedTCPProcess
	open     atomic.Bool
}

func xrayDomainTCPOriginalProcessRead(ctx context.Context, p *xraySelectedTCPProcess) bool {
	if ctx == nil || p == nil {
		return false
	}
	read, ok := ctx.Value(xrayDomainTCPProcessReadKey{}).(*xrayDomainTCPProcessRead)
	if !ok || read == nil || read.self != read || !read.open.Load() || read.process != p {
		return false
	}
	r := read.resource
	return r != nil && r.self == r && !r.descriptorsClosed.Load() && r.child == p && r.scope != nil &&
		r.material != nil && r.material.self == r.material && r.material.resource == r &&
		ctx.Value(syntheticExecutionRegistrarKey{}) == r.scope
}

// The shared process object supplies only its actual Cmd association and sole
// Wait. Domain observation never broadens that object's literal forward/read
// permission or substitutes a renewed initial context for an original owner.
func (r *XrayDomainTCPExecutionResource) domainProcessCurrent(ctx context.Context) error {
	if r == nil || r.self != r || r.child == nil || xraySelectedTCPFinite(ctx) != nil || !xrayDomainTCPOriginalProcessRead(ctx, r.child) ||
		r.child.closed.Load() || r.child.commandCurrent() != nil {
		return ErrXrayDomainTCPOriginal
	}
	select {
	case <-r.child.done:
		return ErrXrayDomainTCPOriginal
	default:
		return nil
	}
}
