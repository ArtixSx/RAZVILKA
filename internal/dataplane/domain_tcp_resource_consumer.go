package dataplane

import (
	"context"
	"errors"
	"time"
)

// RunDomainPolicyTCPResource connects the original Manager's held-descriptor
// Xray owner to the existing accepted-socket capture consumer. The process is
// started exactly once by WithNative and retired only after all capture
// handlers and numeric SOCKS connections have joined. This finite consumer
// does not issue a capture owner or establish DNS publication readiness.
func (a *ProxyTunnelAdapter) RunDomainPolicyTCPResource(ctx context.Context, resource *XrayDomainTCPExecutionResource, owner DomainPolicyTCPCaptureOwner) error {
	if ctx == nil || owner == nil || resource == nil || resource.self != resource || resource.material == nil || resource.material.self != resource.material || resource.material.adapter != a || resource.material.resource != resource || !domainPolicyTCPCaptureSupported() {
		return ErrXrayDomainTCPOriginal
	}
	policy, err := CompileDomainPolicyForPlan(resource.definition.Domain, time.Now().UTC())
	if err != nil {
		return err
	}
	return resource.WithNative(ctx, func(held context.Context) (result error) {
		life, cancel := context.WithCancel(held)
		defer cancel()
		x := &DomainPolicyTCPXray{a: a, resource: resource, spec: resource.definition.Capture.Xray, address: resource.definition.PrivateEndpoint.String(), ctx: life, cancel: cancel, connections: make(map[*domainPolicyTCPXrayConn]struct{})}
		defer x.close()
		if original, ok := owner.(*DomainTCPOriginalScope); ok {
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(held), 12*time.Second)
				defer cancel()
				result = errors.Join(result, original.finishCapture(cleanup, resource))
			}()
		}
		if err := x.check(held); err != nil {
			return err
		}
		return policy.serveDomainPolicyTCPCapture(held, resource.definition.Capture, owner, x)
	})
}

func (x *DomainPolicyTCPXray) checkOriginalResource(ctx context.Context) error {
	if x == nil || ctx == nil || x.ctx == nil || ctx.Err() != nil || x.ctx.Err() != nil || x.resource == nil || x.resource.self != x.resource || x.resource.material == nil || x.resource.material.resource != x.resource || x.resource.material.adapter != x.a || x.spec != x.resource.definition.Capture.Xray || x.address != x.resource.definition.PrivateEndpoint.String() {
		return ErrXrayDomainTCPOriginal
	}
	return errors.Join(x.resource.material.Current(ctx), ctx.Err(), x.ctx.Err())
}
