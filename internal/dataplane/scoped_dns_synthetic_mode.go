package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// This SAME adapter/session mode is finite bootstrap work. CORE has not
// transferred the original Manager owner at Commit, so scope close cancels and
// joins it. The existing Manager's closed runtime check remains in force.
type scopedDNSSyntheticMode struct {
	binding *SyntheticDNSExecutionBinding
	source  *dnscontrol.NetworkPolicyDNSSyntheticResolver
	control *operationgate.ControlEpochReview
}

type scopedDNSSyntheticState struct {
	Schema int    `json:"schema"`
	Mode   string `json:"mode"`
	Plan   Plan   `json:"plan"` // retained intent only; never reconstructs a binding
}

// Private finite source/listener phase. Native DNS INPUT/redirect effects,
// capture/standby registrations and Commit transfer must be performed by the
// original coordinator before Manager can open its execution path. Opening
// these listeners itself grants none of those effects or publication readiness.
func (a *ScopedDNSAdapter) startSyntheticDNSLocked(ctx context.Context, binding *SyntheticDNSExecutionBinding, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview, publication dnscontrol.NetworkPolicyDNSSyntheticPublicationOwner) error {
	if a == nil || binding == nil || binding.self != binding || binding.adapter != a || a.live != nil || resolver == nil || control == nil {
		return ErrDomainTransportRuntime
	}
	if err := binding.Current(ctx); err != nil {
		return err
	}
	if err := resolver.CheckSyntheticAdapterDefinition(ctx, a.DNS, binding.transport.DNS, control, binding.transport.Definition); err != nil {
		return err
	}
	if publication != nil && !sameNetworkPolicyDependency(publication, publication) {
		return ErrDomainTransportRuntime
	}
	endpoint, err := netip.ParseAddrPort(binding.transport.Listener)
	if err != nil {
		return err
	}
	finish := scopedDNSInactiveMutation(a.StateRoot)
	defer finish()
	if _, err := os.Lstat(a.statePath()); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		return err
	}
	life, cancel := context.WithCancel(a.lifetime)
	stopScope := context.AfterFunc(binding.scope.ctx, cancel)
	keep := false
	defer func() {
		if !keep {
			stopScope()
			cancel()
		}
	}()
	owner := &scopedDNSSyntheticPublication{binding: binding, original: publication}
	source, err := dnscontrol.NewNetworkPolicyDNSSyntheticResolver(ctx, life, resolver, control, a.StateRoot, binding.transport.Definition, owner)
	if err != nil {
		return err
	}
	defer func() {
		if !keep {
			_ = source.Close()
		}
	}()
	if err := binding.Current(ctx); err != nil {
		return err
	}
	listen := a.listen
	if listen == nil {
		listen = listenScopedDNS
	}
	udp, tcp, err := listen(endpoint)
	if err != nil {
		return err
	}
	defer func() {
		if !keep {
			_ = udp.Close()
			_ = tcp.Close()
		}
	}()
	if err := syntheticDNSListenerAddress(udp, tcp, endpoint); err != nil {
		return err
	}
	if err := binding.Current(ctx); err != nil {
		return err
	}
	state := scopedDNSSyntheticState{Schema: 1, Mode: "synthetic-tcp", Plan: cloneExecutionResourcePlan(binding.plan)}
	// The shared protected owner location fences cold inactivity/recovery.
	// The old record decoder refuses this distinct mode; it cannot restore it.
	files, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer files.Close()
	if err := source.CheckAdapterBinding(ctx, a.DNS, binding.transport.DNS, control, a.StateRoot, binding.transport.Definition); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > 128<<10 {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := files.WriteAtomic("owner.json", data, 0600); err != nil {
		return err
	}
	mode := &scopedDNSSyntheticMode{binding: binding, source: source, control: control}
	session := &scopedDNSSession{synthetic: mode, done: make(chan struct{}), cancel: func() { stopScope(); cancel() }, resources: scopedDNSInactiveResources{udp: udp, tcp: tcp}}
	scopedDNSInactivePublish(a.StateRoot, session)
	a.live = session
	keep = true
	go session.serve(life)
	// Any closing refusal retains the original owned session/record for Stop.
	return binding.Current(ctx)
}

func syntheticDNSListenerAddress(udp *net.UDPConn, tcp *net.TCPListener, expected netip.AddrPort) error {
	if udp == nil || tcp == nil {
		return ErrDomainTransportRuntime
	}
	u, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || u.AddrPort() != expected {
		return ErrDomainTransportRuntime
	}
	t, ok := tcp.Addr().(*net.TCPAddr)
	if !ok || t.AddrPort() != expected {
		return ErrDomainTransportRuntime
	}
	uf, err := udp.SyscallConn()
	if err != nil {
		return err
	}
	if err := uf.Control(func(uintptr) {}); err != nil {
		return err
	}
	tf, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	return tf.Control(func(uintptr) {})
}

// Revoke original DNS reservations/publication first, then cancel and join the
// SAME listener workers. Retain the owner/ledger/session fence: this operation
// cannot prove selector removal or cache/conntrack/capture settlement and may
// not remove standby rules, reservations, process records or pool addresses.
func (a *ScopedDNSAdapter) stopSyntheticDNSLocked(ctx context.Context) error {
	if ctx == nil || a == nil || a.live == nil || a.live.synthetic == nil {
		return ErrSyntheticBaselineTransition
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrSyntheticBaselineTransition
	}
	s := a.live
	finish := scopedDNSInactiveMutation(a.StateRoot)
	defer finish()
	err := s.synthetic.source.Close()
	err = errors.Join(err, s.synthetic.binding.phase.Close())
	s.resources.cancelled.Store(true)
	s.cancel()
	select {
	case <-s.done:
		return errors.Join(ErrSyntheticBaselineTransition, dnscontrol.ErrSyntheticDNSTransitionPending, err, s.inactiveJoined())
	case <-ctx.Done():
		return errors.Join(ErrSyntheticBaselineTransition, err, ctx.Err())
	}
}

// The wrapper keeps the actual original finite Manager owner in every lower
// coordinator call and through the final DNS publication. It does not turn a
// coordinator interface, successful callback or finite binding into readiness.
type scopedDNSSyntheticPublication struct {
	binding  *SyntheticDNSExecutionBinding
	original dnscontrol.NetworkPolicyDNSSyntheticPublicationOwner
}

func (o *scopedDNSSyntheticPublication) WithSyntheticRequestPhase(ctx context.Context, use func(context.Context) error) error {
	if o == nil || o.binding == nil || o.binding.self != o.binding || o.binding.phase == nil {
		return ErrSyntheticBaselineTransition
	}
	return o.binding.phase.WithRequest(ctx, use)
}

func (o *scopedDNSSyntheticPublication) valid() bool {
	return o != nil && o.binding != nil && o.original != nil && reflect.ValueOf(o.original).Comparable() && sameNetworkPolicyDependency(o.original, o.original)
}
func (o *scopedDNSSyntheticPublication) WithSyntheticPublication(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, consume func(context.Context) error) error {
	if !o.valid() || mapping == nil || consume == nil {
		return ErrSyntheticBaselineTransition
	}
	if err := o.binding.Current(ctx); err != nil {
		return err
	}
	err := o.original.WithSyntheticPublication(ctx, mapping, func(held context.Context) error {
		if err := o.binding.Current(held); err != nil {
			return err
		}
		err := consume(held)
		return errors.Join(err, o.binding.Current(held))
	})
	return errors.Join(err, o.binding.Current(ctx))
}
func (o *scopedDNSSyntheticPublication) CurrentSyntheticMapping(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping) error {
	if !o.valid() || mapping == nil {
		return ErrSyntheticBaselineTransition
	}
	if err := o.binding.Current(ctx); err != nil {
		return err
	}
	err := o.original.CurrentSyntheticMapping(ctx, mapping)
	return errors.Join(err, o.binding.Current(ctx))
}
