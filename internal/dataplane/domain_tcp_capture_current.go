package dataplane

import (
	"context"
	"errors"
	"net"
	"reflect"
)

// One current read of the concrete original capture uses its SAME resource's
// complete material/child/file/network comparison. Public CheckCapture and
// generic Xray source checks retain their independent full paths. This read
// creates no reusable proof and does not span any effect or publication.
func (c *DomainPolicyTCPCapture) currentOriginalResource(ctx context.Context, owner *DomainTCPOriginalScope, files *xrayDomainTCPFileObservation) error {
	if c == nil || owner == nil || c.xray == nil || c.xray.resource == nil {
		return ErrDomainPolicyTCPConsumer
	}
	xray, process, listener := c.xray, c.xray.resource, c.listener
	material, binding := process.material, owner.binding
	if err := c.originalReadAssociation(ctx, owner, xray, process, material, binding, listener); err != nil {
		return err
	}
	if err := owner.baseCurrent(ctx); err != nil {
		return err
	}
	if err := c.originalReadAssociation(ctx, owner, xray, process, material, binding, listener); err != nil {
		return err
	}
	// Even a file view only brackets immutable bytes. The actual resource
	// still runs originalContext -> material.Current and every live child,
	// journal, registry, config and network check on EVERY invocation.
	result := process.currentWithFiles(ctx, files)
	closing := c.originalReadAssociation(ctx, owner, xray, process, material, binding, listener)
	if closing == nil {
		closing = errors.Join(owner.baseAssociationCurrent(), c.originalReadAssociation(ctx, owner, xray, process, material, binding, listener))
	}
	return errors.Join(result, closing, ctx.Err())
}

// Local association comparisons only. A nil return does not establish a live
// material, source, process or runtime; currentOriginalResource must run the
// original resource's complete comparison between two calls to this helper.
func (c *DomainPolicyTCPCapture) originalReadAssociation(ctx context.Context, owner *DomainTCPOriginalScope, xray *DomainPolicyTCPXray, process *XrayDomainTCPExecutionResource, material *XrayDomainTCPOperationMaterial, binding *SyntheticDNSExecutionBinding, listener *net.TCPListener) error {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || c.ctx == nil || c.ctx.Err() != nil || owner == nil || owner.self != owner || c.owner != owner || c.xray != xray || xray == nil || xray.ctx == nil || xray.ctx.Err() != nil || xray.resource != process || process == nil || process.self != process || process.material != material || material == nil || material.self != material || material.resource != process || material.adapter != xray.a || owner.binding != binding || binding == nil || binding.self != binding || material.binding != binding || process.scope != binding.scope || xray.spec != process.definition.Capture.Xray || xray.address != process.definition.PrivateEndpoint.String() || listener == nil || c.listener != listener || !reflect.DeepEqual(c.spec, process.definition.Capture) {
		return ErrDomainPolicyTCPConsumer
	}
	owner.mu.Lock()
	same := owner.process == process && owner.capture == c && !owner.closed
	owner.mu.Unlock()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if !same || closed || listener.Addr().(*net.TCPAddr).AddrPort() != c.spec.Listen {
		return ErrDomainPolicyTCPConsumer
	}
	raw, err := listener.SyscallConn()
	if err != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return errors.Join(raw.Control(func(uintptr) {}), ctx.Err(), c.ctx.Err(), xray.ctx.Err())
}
