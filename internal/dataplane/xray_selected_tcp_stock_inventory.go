package dataplane

import (
	"context"
	"errors"
	"reflect"
)

type networkPolicyXraySelectedTCPStockObservation struct {
	checks   *NetworkPolicyChecks
	resource *XraySelectedTCPExecutionResource
	record   ExecutionResource
}

// Only this SAME collector and actual original Xray scope can introduce the
// foreign stock OUTPUT comparison. Missing context stays strict. No queue,
// native inventory DTO, chain name or copied resource can construct this owner.
func (c *NetworkPolicyChecks) xraySelectedTCPStockExecution(ctx context.Context) (*networkPolicyXraySelectedTCPStockObservation, error) {
	if c == nil || ctx == nil {
		return nil, ErrNetworkPolicyConsumers
	}
	value := ctx.Value(xrayOperationOwnerKey{})
	if value == nil {
		return nil, nil
	}
	o, ok := value.(*xrayOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.material == nil || o.material.self != o.material ||
		ctx.Value(xrayOperationMaterialKey{}) != o.material || c.identity == nil || c.inventory == nil || c.gate == nil || c.gate.identity != c.identity ||
		!c.identity.acceptsMode(LANPolicyXraySelectedTCPMode) || o.scope.plan.LAN == nil || o.scope.plan.LAN.Mode != LANPolicyXraySelectedTCPMode ||
		o.scope.manager != c.manager || o.scope.managerRoot != c.root || o.scope.networkIdentity != c.identity ||
		o.scope.adapterOwner != c.adapters["xray"] || o.material.adapter != c.adapters["xray"] ||
		c.inventory.reader.Provider != c.identity.provider || c.network != c.identity.value {
		return nil, ErrNetworkPolicyConsumers
	}
	cleanup := o.material.IsCleanupContext(ctx)
	if err := o.checkHeld(ctx, cleanup); err != nil {
		return nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	s := o.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.xraySelectedTCP) != 1 || !s.open || !s.observationOpen.Load() {
		return nil, ErrNetworkPolicyConsumers
	}
	var r *XraySelectedTCPExecutionResource
	for _, resource := range s.xraySelectedTCP {
		r = resource
	}
	if r == nil || r.owner != o || r.material != o.material || r.definition.NetworkIdentity != c.network {
		return nil, ErrNetworkPolicyConsumers
	}
	index, err := r.matching()
	if err != nil {
		return nil, err
	}
	return &networkPolicyXraySelectedTCPStockObservation{checks: c, resource: r, record: cloneExecutionResources([]ExecutionResource{s.execution.Resources[index]})[0]}, nil
}

func (o *networkPolicyXraySelectedTCPStockObservation) equal(other *networkPolicyXraySelectedTCPStockObservation) bool {
	if o == nil || other == nil {
		return o == other
	}
	return o.checks == other.checks && o.resource == other.resource && reflect.DeepEqual(o.record, other.record)
}

// Pure final bookend. Provider, file/source, process and physical observations
// bracket the actual captures elsewhere; no callback follows the last image.
func (o *networkPolicyXraySelectedTCPStockObservation) current(ctx context.Context) error {
	if o == nil {
		return nil
	}
	r := o.resource
	if xraySelectedTCPFinite(ctx) != nil || r == nil || r.self != r || r.scope == nil || r.material == nil || r.material.closed.Load() ||
		ctx.Value(xrayOperationOwnerKey{}) != r.owner || ctx.Value(xrayOperationMaterialKey{}) != r.material {
		return ErrNetworkPolicyConsumers
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	index, err := r.matching()
	if err != nil || !r.scope.open || !r.scope.observationOpen.Load() || !reflect.DeepEqual(o.record, r.scope.execution.Resources[index]) {
		return ErrNetworkPolicyConsumers
	}
	return nil
}

func (o *networkPolicyXraySelectedTCPStockObservation) comparison(actual BackendInventorySnapshot) ([]BackendInventoryRow, error) {
	if o == nil {
		return nil, nil
	}
	c := o.checks
	if c == nil || c.inventory == nil || actual.Scope.Network != o.resource.definition.NetworkIdentity || actual.Scope.Network != c.network ||
		actual.Scope.ToolReviewID != c.inventory.review || actual.IPTables != c.inventory.reader.IPTables || actual.IP6Tables != c.inventory.reader.IP6Tables {
		return nil, ErrNetworkPolicyConsumers
	}
	// This predicate authenticates only foreign stock OUTPUT rows. Original NAT
	// RZX allowances still require actual COMMON and native consumer witnesses.
	return inspectXrayStockOutputQueues(actual)
}
