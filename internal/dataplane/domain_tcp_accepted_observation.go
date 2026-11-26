package dataplane

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// An original accepted flow can use the completed prefix read for the
// immediately following client-only decision. This carries no borrowed file,
// packet inventory, or authorization to dial. Original Guard still runs after
// sniffing, before dialing, and before replaying bytes on the new connection.
type domainTCPAcceptedFlow struct {
	prefix   domainTCPAcceptedPrefix
	capture  *DomainPolicyTCPCapture
	prepared *DomainPolicyTCPCaptureMapping
	lease    *domainTCPOriginalFlowLease
	initial  atomic.Bool
}

func newDomainTCPAcceptedFlow(prefix domainTCPAcceptedPrefix, capture *DomainPolicyTCPCapture, prepared *DomainPolicyTCPCaptureMapping) *domainTCPAcceptedFlow {
	lease, ok := prefix.lease.(*domainTCPOriginalFlowLease)
	if !prefix.closedRead || !ok || lease == nil {
		return nil
	}
	return &domainTCPAcceptedFlow{prefix: prefix, capture: capture, prepared: prepared, lease: lease}
}

func (a *domainTCPAcceptedFlow) scopeBeforeSniff(ctx context.Context, policy *DomainPolicy, conn net.Conn, flow DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok || a == nil || a.prefix.accepted == nil || a.prefix.accepted.conn != tcp || a.capture == nil || a.capture.policy != policy || !a.initial.CompareAndSwap(false, true) {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	return a.currentScope(ctx, flow)
}

func (a *domainTCPAcceptedFlow) currentScope(ctx context.Context, flow DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
	if a == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != a.prefix.flowContext || ctx.Err() != nil ||
		!a.prefix.closedRead || flow != a.prefix.flow || a.prefix.binding == nil || !a.prefix.binding.matches(flow) ||
		a.capture == nil || a.capture.self != a.capture || a.prepared == nil || a.prepared.self != a.prepared || a.prepared.capture != a.capture || a.prepared.ctx == nil ||
		a.lease == nil || a.lease.self != a.lease || a.lease.accepted != a.prefix.accepted || a.lease.mapping != a.prepared.source || a.lease.owner == nil {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	owner := a.lease.owner
	if owner.self != owner || a.capture.owner != owner || a.capture.policy == nil || a.prefix.kernel == nil {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	owner.mu.Lock()
	current := owner.publicationOpen && !owner.closed && owner.capture == a.capture && owner.prepared == a.prepared && owner.kernel == a.prefix.kernel && owner.process != nil
	owner.mu.Unlock()
	if !current || a.prepared.ctx.Err() != nil || !time.Now().Before(a.prefix.binding.mapping.ExpiresAt) {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	if err := a.lease.accepted.current(ctx, a.capture, a.lease.socket); err != nil {
		return autonomy.ScopeObservation{}, err
	}
	if err := owner.baseCurrent(ctx); err != nil {
		return autonomy.ScopeObservation{}, err
	}
	if err := a.lease.mapping.Current(ctx); err != nil {
		return autonomy.ScopeObservation{}, err
	}
	scope := cloneDomainPolicyScope(a.capture.policy.scope)
	if !time.Now().Before(scope.FreshUntil) {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	return scope, ctx.Err()
}

// The only consumer is HandleTCP's existing forwardTCP, which makes the
// fresh pre-dial Guard its first action. Claiming the original one-shot lease
// does not admit an outbound or share a completed check with it.
func (a *domainTCPAcceptedFlow) withFlow(ctx context.Context, flow DomainPolicyTCPFlow, decision DomainPolicyDecision, forward func(context.Context) error) error {
	if a == nil || !a.initial.Load() || decision.Generation != flow.Generation {
		return ErrDomainPolicyTCPConsumer
	}
	if _, err := a.currentScope(ctx, flow); err != nil {
		return err
	}
	return a.lease.consume(ctx, forward)
}

// Only the same accepted flow may run the next pure decision inside Guard's
// byte observation. The authority checks and both kernel passes of the
// baseline decision still run. Each sniff, dial, and relay boundary gets a
// separate observation, which closes before the decision becomes usable.
func (a *domainTCPAcceptedFlow) readDecision(ctx context.Context, policy *DomainPolicy, flow DomainPolicyTCPFlow, question DomainPolicyFlow, runtime DomainPolicyTCPRuntime, boundary string) (DomainPolicyDecision, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !a.initial.Load() || a.capture == nil || a.capture.policy != policy || a.prepared == nil || a.lease == nil ||
		a.prefix.binding == nil || !a.prefix.closedRead || flow != a.prefix.flow || !a.prefix.binding.matches(flow) ||
		a.prefix.kernel == nil || a.prefix.kernel != runtime.originalBaseline || a.prefix.accepted == nil || a.lease.accepted != a.prefix.accepted ||
		ctx.Value(domainAcceptedTCPKey{}) != a.prefix.accepted {
		return DomainPolicyDecision{}, ErrDomainPolicyTCPConsumer
	}
	mapping, id := a.lease.Binding()
	if mapping == nil || mapping != a.prepared.source || id != a.prefix.flowID || !time.Now().Before(a.prefix.binding.mapping.ExpiresAt) {
		return DomainPolicyDecision{}, ErrDomainPolicyTCPConsumer
	}
	var decision DomainPolicyDecision
	_, err := a.capture.guardPreparedFlowThen(ctx, mapping, a.prepared, a.lease, a.prefix.accepted.socket, func(observed context.Context, scope autonomy.ScopeObservation, files *xrayDomainTCPFileObservation) error {
		finish := domainTCPMeasureForwardStage(ctx, boundary, "decision") // Nested within the closing guard's diagnostic span.
		var err error
		decision, err = policy.decideTCPWithBaselineFrom(observed, flow, question, scope, runtime, files)
		finish(err)
		return err
	})
	if err != nil {
		return DomainPolicyDecision{}, err
	}
	if decision.Kind == "" || !time.Now().Before(a.prefix.binding.mapping.ExpiresAt) {
		return DomainPolicyDecision{}, ErrDomainPolicyTCPConsumer
	}
	return decision, nil
}

// Bracket only the existing pure Guard and decision comparisons. Neither sniffing nor
// WithFlow/Dial/Connect/Start borrows these facts; they run after this callback
// has joined and the original file/tool SHA closing observations succeeded.
func (c *DomainPolicyTCPCapture) guardPreparedFlow(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, prepared *DomainPolicyTCPCaptureMapping, lease DomainPolicyTCPFlowLease, socket DomainPolicyTCPSocket) (autonomy.ScopeObservation, error) {
	return c.guardPreparedFlowThen(ctx, mapping, prepared, lease, socket, nil)
}

func (c *DomainPolicyTCPCapture) guardPreparedFlowThen(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, prepared *DomainPolicyTCPCaptureMapping, lease DomainPolicyTCPFlowLease, socket DomainPolicyTCPSocket, decide func(context.Context, autonomy.ScopeObservation, *xrayDomainTCPFileObservation) error) (autonomy.ScopeObservation, error) {
	finish := domainTCPMeasure("accepted-flow-guard")
	defer finish(0)
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || mapping == nil || prepared == nil || prepared.self != prepared || prepared.capture != c || prepared.source != mapping || lease == nil {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	original, ok := lease.(*domainTCPOriginalFlowLease)
	if !ok {
		if decide != nil {
			return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
		}
		if err := prepared.Current(ctx); err != nil {
			return autonomy.ScopeObservation{}, err
		}
		return lease.Guard(ctx, socket)
	}
	if original == nil || original.self != original || original.owner != c.owner || original.mapping != mapping || original.socket != socket {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	var result autonomy.ScopeObservation
	err := c.observePreparationClosing(ctx, mapping, func(observed context.Context, files *xrayDomainTCPFileObservation) error {
		if err := prepared.currentWithFiles(observed, files); err != nil {
			return err
		}
		var err error
		result, err = original.guardWithFiles(observed, socket, files)
		if err != nil || decide == nil {
			return err
		}
		return decide(observed, result, files)
	})
	if err = errors.Join(err, ctx.Err()); err != nil {
		return autonomy.ScopeObservation{}, err
	}
	return result, nil
}
