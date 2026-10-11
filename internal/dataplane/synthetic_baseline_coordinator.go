package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Concrete original source aggregate, retained in the SAME COMMON scope.
// The caller is the actual opened WithCapture producer and supplies the tools
// obtained once from its original retained StartupTools Lease. This aggregate
// does not grant publication, firmware equivalence or Commit transfer.
type syntheticBaselineCoordinator struct {
	self        *syntheticBaselineCoordinator
	binding     *SyntheticDNSExecutionBinding
	tools       *SyntheticDNSCommandTools
	toolsFrozen SyntheticDNSCommandTools
	backend     *BackendInventory
	capture     *DomainPolicyTCPCapture
	control     *operationgate.ControlEpochReview
}

func (*syntheticBaselineCoordinator) String() string {
	return "[original COMMON synthetic baseline coordinator source]"
}
func (*syntheticBaselineCoordinator) GoString() string {
	return "[original COMMON synthetic baseline coordinator source]"
}

// No exported factory or callback accepts DTOs as source authority. The real
// opened listener, registered process and original finite Manager operation
// must already exist; capture.Current authenticates that original ownership.
func (b *SyntheticDNSExecutionBinding) bindBaselineCoordinator(ctx context.Context, tools *SyntheticDNSCommandTools, backend *BackendInventory, capture *DomainPolicyTCPCapture) (*syntheticBaselineCoordinator, error) {
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	control, err := b.baselineControl()
	if err != nil {
		return nil, err
	}
	c := &syntheticBaselineCoordinator{binding: b, tools: tools, backend: backend, capture: capture, control: control}
	c.self = c
	if tools == nil {
		return nil, ErrSyntheticBaselineTransition
	}
	c.toolsFrozen = *tools
	if err := c.Current(ctx); err != nil {
		return nil, err
	}
	if err := b.scope.registerSyntheticBaselineCoordinator(ctx, c); err != nil {
		return nil, err
	}
	return c, c.Current(ctx)
}

func (b *SyntheticDNSExecutionBinding) baselineControl() (*operationgate.ControlEpochReview, error) {
	if b == nil || b.self != b || b.adapter == nil {
		return nil, ErrSyntheticBaselineTransition
	}
	b.adapter.mu.Lock()
	session := b.adapter.live
	var control *operationgate.ControlEpochReview
	if session != nil && session.synthetic != nil && session.synthetic.binding == b {
		control = session.synthetic.control
	}
	b.adapter.mu.Unlock()
	if control == nil {
		return nil, ErrSyntheticBaselineTransition
	}
	if _, err := b.originalSyntheticSession(control); err != nil {
		return nil, err
	}
	return control, nil
}

// Pure local source comparisons, safe inside the retained tool source lock.
func (c *syntheticBaselineCoordinator) local(ctx context.Context) error {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || c.binding == nil || c.binding.self != c.binding || c.binding.scope == nil || c.binding.scope.networkIdentity == nil || c.binding.transport == nil || c.binding.domain == nil || c.control == nil || c.capture == nil || c.capture.self != c.capture || c.capture.owner == nil || c.backend == nil || !c.tools.valid() {
		return ErrSyntheticBaselineTransition
	}
	d := c.binding.transport.Definition
	s := c.capture.spec
	if s.Client.Address != d.Client || s.DeviceID != d.DeviceID || s.Client.MAC != d.MAC || s.Client.Interface != d.Ingress || !slices.Contains(d.ExactNames, s.Xray.Name) || c.capture.xray == nil || c.capture.xray.a == nil {
		return ErrSyntheticBaselineTransition
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrSyntheticBaselineTransition
	}
	if ctx.Value(syntheticExecutionRegistrarKey{}) != c.binding.scope || !reflect.DeepEqual(*c.tools, c.toolsFrozen) || c.tools.Provider != c.binding.scope.networkIdentity.provider || c.tools.Identity != c.binding.scope.networkIdentity.value || c.backend.reader.Provider != c.tools.Provider || c.backend.review != c.tools.ReviewSHA256 || c.backend.reader.IPTables != c.tools.IPTables || c.capture.spec.Listen.String() != c.binding.transport.CaptureEndpoint || c.capture.spec.Xray.Generation != c.binding.domain.Generation {
		return ErrSyntheticBaselineTransition
	}
	return nil
}

func (c *syntheticBaselineCoordinator) Current(ctx context.Context) error {
	if err := c.local(ctx); err != nil {
		return err
	}
	if err := c.binding.Current(ctx); err != nil {
		return err
	}
	control, err := c.binding.baselineControl()
	if err != nil || control != c.control {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := c.capture.Current(ctx); err != nil {
		return err
	}
	m := c.binding.scope.manager
	m.registryMu.RLock()
	registered := m.Adapters["xray"] == c.capture.xray.a
	m.registryMu.RUnlock()
	if !registered {
		return ErrSyntheticBaselineTransition
	}
	endpoint, err := c.capture.Address()
	if err != nil || endpoint.String() != c.binding.transport.CaptureEndpoint {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := c.tools.Runner.CheckSyntheticDNS(ctx, c.tools.Identity); err != nil {
		return err
	}
	if err := c.control.Current(ctx); err != nil {
		return err
	}
	if err := c.capture.Current(ctx); err != nil {
		return err
	}
	if err := c.binding.Current(ctx); err != nil {
		return err
	}
	return c.local(ctx)
}
