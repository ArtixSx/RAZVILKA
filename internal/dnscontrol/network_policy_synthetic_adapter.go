package dnscontrol

import (
	"context"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Comparison and current-source validation for the SAME adapter factory.
// It cannot grant INPUT, listener, redirect, capture or publication readiness.
// A resolver created from loose bindings or a reconstructed plan cannot pass.
func (r *NetworkPolicyDNSResolver) CheckSyntheticAdapterDefinition(ctx context.Context, original *Manager, expected *NetworkPolicyDNSPlan, control *operationgate.ControlEpochReview, definition SyntheticDNSDefinition) error {
	if r == nil || r.self != r || ctx == nil || original == nil || control == nil || r.defaultDNS == nil || r.defaultDNS.manager != original || r.operations == nil || r.frozenPlan == nil || !reflect.DeepEqual(r.frozenPlan, expected) || !validSyntheticDNSDefinition(definition) || r.authority.Generation != expected.Generation || r.authority.Exclusions != expected.Exclusions || r.authority.ControlEpoch != control.Reference().Sequence {
		return ErrSyntheticDNSMapping
	}
	return networkPolicyDNSOperation(ctx, r.operations, func(held context.Context) error {
		if err := control.Current(held); err != nil {
			return err
		}
		if err := original.CheckNetworkPolicyDNSPlan(held, r.frozenPlan, r.exclusions); err != nil {
			return err
		}
		admission, err := r.admission(held, definition.Client, "")
		if err != nil {
			return err
		}
		if admission.DeviceID != definition.DeviceID || admission.Ingress != definition.Ingress || admission.Authority != r.authority {
			return ErrSyntheticDNSMapping
		}
		return control.Current(held)
	})
}

func (s *NetworkPolicyDNSSyntheticResolver) CheckAdapterBinding(ctx context.Context, original *Manager, expected *NetworkPolicyDNSPlan, control *operationgate.ControlEpochReview, root string, definition SyntheticDNSDefinition) error {
	if s == nil || s.self != s || s.resolver == nil || s.control != control || s.root != root {
		return ErrSyntheticDNSMapping
	}
	definition.ExactNames = slices.Clone(definition.ExactNames)
	slices.Sort(definition.ExactNames)
	if !reflect.DeepEqual(s.definition, definition) {
		return ErrSyntheticDNSMapping
	}
	if err := s.resolver.CheckSyntheticAdapterDefinition(ctx, original, expected, control, definition); err != nil {
		return err
	}
	return s.current(ctx)
}
