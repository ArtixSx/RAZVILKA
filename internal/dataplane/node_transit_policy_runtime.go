package dataplane

import (
	"context"
	"reflect"
)

// This private carrier is not an observed permission. Only the original lease
// factory can supply it; normalization rejects mixed callback roles outright.
type nodeTransitPolicyRuntimeOrigin struct {
	self  *nodeTransitPolicyRuntimeOrigin
	lease *nodeTransitLease
}

func newNodeTransitPolicyRuntimeOrigin(l *nodeTransitLease) *nodeTransitPolicyRuntimeOrigin {
	// Even an invalid attempted opt-in retains its carrier and must be refused
	// by normalization BEFORE a session creates a lock/receipt. Nil means only
	// that no opt-in was attempted; it must never hide a copied original.
	o := &nodeTransitPolicyRuntimeOrigin{lease: l}
	o.self = o
	return o
}

// The original receipt session retains this binding separately from public
// runtime callback fields. A copied/modified callback struct cannot replace
// the exact original guarded presence reader selected by the constructor.
type nodeTransitPolicyRuntimeBinding struct {
	self   *nodeTransitPolicyRuntimeBinding
	origin *nodeTransitPolicyRuntimeOrigin
	plan   PolicyEffectPlan
	root   string
}

// normalizeNodeTransitPolicyRuntime performs no IO or effect. Its input must
// carry ONLY the original runner/tools and no independently supplied callbacks.
// Its full original callbacks are internal output, never another opt-in input.
func normalizeNodeTransitPolicyRuntime(origin *nodeTransitPolicyRuntimeOrigin, in PolicyEffectRuntime, plan PolicyEffectPlan, root string) (PolicyEffectRuntime, *nodeTransitPolicyRuntimeBinding, error) {
	if origin == nil || origin.self != origin || origin.lease == nil || in.nodeTransitOrigin != origin {
		return PolicyEffectRuntime{}, nil, ErrNodeTransitUnavailable
	}
	l := origin.lease
	if !l.runtime.sharedOwner.validFor(l) || root != l.root || in.Guard != nil || in.ExactPresence != nil || in.Preflight != nil || in.BeforeDelete != nil || in.Tools != (PolicyEffectTools{IP: l.runtime.ip}) || !sameNodeTransitPolicyRunner(in.Runner, l.runtime.runner) {
		return PolicyEffectRuntime{}, nil, ErrNodeTransitUnavailable
	}
	copy, _, err := copyPolicyEffectPlan(plan)
	if err != nil || !reflect.DeepEqual(copy, l.plan) {
		return PolicyEffectRuntime{}, nil, ErrNodeTransitUnavailable
	}
	b := &nodeTransitPolicyRuntimeBinding{origin: origin, plan: copy, root: root}
	b.self = b
	return l.effectRuntime(), b, nil
}

func preparePolicyEffectRuntime(in PolicyEffectRuntime, plan PolicyEffectPlan, root string) (PolicyEffectRuntime, *nodeTransitPolicyRuntimeBinding, error) {
	if in.nodeTransitOrigin == nil {
		return in, nil, nil
	}
	return normalizeNodeTransitPolicyRuntime(in.nodeTransitOrigin, in, plan, root)
}

func sameNodeTransitPolicyRunner(a, b NFQWS2Runner) bool {
	if a == nil || b == nil || reflect.TypeOf(a) != reflect.TypeOf(b) || !reflect.TypeOf(a).Comparable() {
		return false
	}
	if reflect.ValueOf(a).Kind() == reflect.Pointer && (reflect.ValueOf(a).IsNil() || reflect.ValueOf(b).IsNil()) {
		return false
	}
	return a == b
}

func (b *nodeTransitPolicyRuntimeBinding) validFor(plan PolicyEffectPlan, root string) bool {
	return b != nil && b.self == b && b.origin != nil && b.origin.self == b.origin && b.origin.lease != nil && b.origin.lease.runtime.sharedOwner.validFor(b.origin.lease) && root == b.root && root == b.origin.lease.root && reflect.DeepEqual(plan, b.plan) && reflect.DeepEqual(plan, b.origin.lease.plan)
}

// Comparison only: always execute the original full opening/closing ownership
// guard around BOTH-family actual reads. No previous result or callback flag
// enters this method. No command-start guard is removed by this constructor.
func (b *nodeTransitPolicyRuntimeBinding) presence(ctx context.Context, plan PolicyEffectPlan, root string, index int) (int, error) {
	if ctx == nil || !b.validFor(plan, root) || index != 0 {
		return 0, ErrNodeTransitUnavailable
	}
	return b.origin.lease.presence(ctx)
}
