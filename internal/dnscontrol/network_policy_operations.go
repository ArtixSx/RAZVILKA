package dnscontrol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const networkPolicyDNSOperationTimeout = 12 * time.Second

// The actual publisher admits the original operation before observe enters the
// SAME Store negative boundary. Its protected Stop lock spans write only, with
// no owner/Gate reentry. write is bounded local serialization and socket IO.
type NetworkPolicyDNSReplyPublisher func(context.Context, NetworkPolicyDNSAdmission, func(func() error) error, func() error) error

// This concrete constructor installs short ORIGINAL admissions once, before any
// concurrent use. Provider exchange never retains them. Guards receive real live
// ExclusiveContext capabilities, not shared-context imitations. No cache is copied.
func (m *Manager) NewNetworkPolicyDNSResolverForPlanWithOperations(ctx context.Context, plan *NetworkPolicyDNSPlan, authority NetworkPolicyDNSAuthority, operations *operationgate.Gate, guard func(context.Context) error, admit func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error), exclusions *NetworkPolicyDNSExclusions) (*NetworkPolicyDNSResolver, error) {
	if operations == nil || guard == nil || admit == nil {
		return nil, ErrNetworkPolicyDNS
	}
	observedGuard := func(ctx context.Context) error { return networkPolicyDNSOperation(ctx, operations, guard) }
	observedAdmit := func(ctx context.Context, client netip.Addr, name string) (NetworkPolicyDNSAdmission, error) {
		var admission NetworkPolicyDNSAdmission
		err := networkPolicyDNSOperation(ctx, operations, func(held context.Context) error {
			var err error
			admission, err = admit(held, client, name)
			return err
		})
		return admission, err
	}
	r, err := m.NewNetworkPolicyDNSResolverForPlan(ctx, plan, authority, observedGuard, observedAdmit, exclusions)
	if err != nil {
		return nil, err
	}
	r.operations = operations
	return r, nil
}

// Borrow only a validated SAME Gate admission, or wait for a new finite one.
// No upstream IO belongs in use; cancellation/fencing ends the wait.
func networkPolicyDNSOperation(ctx context.Context, gate *operationgate.Gate, use func(context.Context) error) error {
	if ctx == nil || gate == nil || use == nil {
		return ErrNetworkPolicyDNS
	}
	bounded, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
	defer cancel()
	borrowed := false
	if err := gate.WithExclusiveContext(bounded, func() error { borrowed = true; return use(bounded) }); borrowed {
		return err
	}
	for {
		held, release, err := gate.ExclusiveContext(bounded)
		if err == nil {
			defer release()
			return gate.WithExclusiveContext(held, func() error { return use(held) })
		}
		if !errors.Is(err, operationgate.ErrBusy) {
			return err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return bounded.Err()
		case <-timer.C:
		}
	}
}

// ServeWithOperations preserves the SAME listener/workers/session lifecycle.
// Original read validators obtain short admissions; upstream is outside Gate.
// Final checks and publication share a fresh operation, with no upstream IO.
func (r *NetworkPolicyDNSResolver) ServeWithOperations(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener, operations *operationgate.Gate, publish NetworkPolicyDNSReplyPublisher) error {
	if r == nil || ctx == nil || operations == nil || r.operations != operations || publish == nil {
		return ErrNetworkPolicyDNS
	}
	if r.service != nil {
		defer r.service.cache.clear()
	}
	return ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
		Admit: func(ctx context.Context, client netip.Addr) error {
			bounded, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
			defer cancel()
			_, err := r.admission(bounded, client, "")
			return err
		},
		Exchange: func(ctx context.Context, client netip.Addr, query []byte, send func([]byte) error) error {
			bounded, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
			defer cancel()
			return r.publishWithOperations(bounded, client, query, publish, send)
		},
	})
}

func (r *NetworkPolicyDNSResolver) publishWithOperations(ctx context.Context, client netip.Addr, query []byte, publish NetworkPolicyDNSReplyPublisher, send func([]byte) error) error {
	var before NetworkPolicyDNSAdmission
	wire, err := r.resolve(ctx, client, query, &before)
	if err != nil {
		return err
	}
	resolvedAt := r.now()
	q, _, err := scopedBaselineQuestion(query)
	if err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), "."))
	return networkPolicyDNSOperation(ctx, r.operations, func(held context.Context) error {
		observe, write, err := r.preparePublication(held, client, name, before, wire, resolvedAt, send)
		if err != nil {
			return err
		}
		return publish(held, before, observe, write)
	})
}
