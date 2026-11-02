package dataplane

import (
	"context"
	"sync/atomic"
)

// Only the local original probe factory uses this one-use declaration that
// preflight/guard/beforeDelete are the SAME ownership check. It is not a
// cached result, a public DTO or an authority to issue a transit rule.
type nodeTransitSharedOwner struct {
	self  *nodeTransitSharedOwner
	spec  NodeTransitSpec
	root  string
	check func(context.Context, NodeTransitSpec) error
	lease atomic.Pointer[nodeTransitLease]
}

func newNodeTransitSharedOwner(spec NodeTransitSpec, root string, check func(context.Context, NodeTransitSpec) error) *nodeTransitSharedOwner {
	owner := &nodeTransitSharedOwner{spec: spec, root: root, check: check}
	owner.self = owner
	return owner
}
func (o *nodeTransitSharedOwner) validFor(l *nodeTransitLease) bool {
	return o != nil && o.self == o && o.check != nil && l != nil && l.runtime.sharedOwner == o && o.lease.Load() == l && o.spec == l.spec && o.root == l.root
}
func (o *nodeTransitSharedOwner) run(l *nodeTransitLease, ctx context.Context, spec NodeTransitSpec) error {
	if !o.validFor(l) || spec != o.spec {
		return ErrNodeTransitUnavailable
	}
	return o.check(ctx, spec)
}
