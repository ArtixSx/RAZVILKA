package dataplane

import (
	"context"
	"sync/atomic"
)

type xraySelectedTCPProcessReadKey struct{}
type xraySelectedTCPProcessRead struct {
	self     *xraySelectedTCPProcessRead
	resource *XraySelectedTCPExecutionResource
	process  *xraySelectedTCPProcess
	open     atomic.Bool
}

// This private read interval belongs to the original live resource, after its
// actual fresh operation/cleanup guard. It grants only observation of the SAME
// child; cancellation of the initial request still prohibits forward admission.
func xraySelectedTCPOriginalProcessRead(ctx context.Context, p *xraySelectedTCPProcess) bool {
	if ctx == nil || p == nil {
		return false
	}
	read, ok := ctx.Value(xraySelectedTCPProcessReadKey{}).(*xraySelectedTCPProcessRead)
	if !ok || read == nil || read.self != read || !read.open.Load() || read.process != p {
		return false
	}
	r := read.resource
	return r != nil && r.self == r && r.child == p && r.owner != nil &&
		ctx.Value(xrayOperationOwnerKey{}) == r.owner && ctx.Value(xrayOperationMaterialKey{}) == r.material
}

// Caller holds the actual resource mutex through the whole bounded read.
func (r *XraySelectedTCPExecutionResource) originalProcessReadContext(ctx context.Context, cleanup bool) (context.Context, func(), error) {
	var c context.Context
	var err error
	if cleanup {
		c, err = r.owner.cleanupContext(ctx)
	} else {
		c, err = r.owner.context(ctx)
	}
	if err != nil || r.child == nil || r.descriptorsClosed {
		return nil, nil, errXraySelectedTCPRuntime
	}
	read := &xraySelectedTCPProcessRead{resource: r, process: r.child}
	read.self = read
	read.open.Store(true)
	c = context.WithValue(c, xraySelectedTCPProcessReadKey{}, read)
	return c, func() { read.open.Store(false) }, nil
}
