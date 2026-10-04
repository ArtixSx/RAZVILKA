package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

// DomainPolicyTCPFlow comes ONLY from the existing admitted capture owner. An
// ordinary loopback SOCKS address, DNS answer, MAC lookup by destination or
// matching kernel tuple cannot supply it. FlowID binds the actual original
// tuple and physical admission to this generation's existing flow lease.
// The first consumer slice is public IPv4 TCP 80/443; other coverage refuses.
type DomainPolicyTCPFlow struct {
	Generation      string
	FlowID          string
	Source          netip.AddrPort
	Destination     netip.AddrPort
	Client          autonomy.ClientPacket
	DefaultCoverage string
	Coalesced       bool
}

// DomainPolicyTCPRuntime is the existing engine's synchronous flow seam. Guard
// proves current control/generation, exact original tuple, physical gate and
// current scope. Lease must call forward once, synchronously, under a revocable
// context and join it before returning. Dial receives the original destination,
// never a hostname. BaselineDial requires that owner's separate baseline proof;
// a plain default/direct socket is not a physical LAN baseline grant.
// There is no listener, independent manager, worker registry, journal or epoch.
type DomainPolicyTCPRuntime struct {
	Limits       DomainPolicySniffLimits
	Guard        func(context.Context, DomainPolicyTCPFlow) (autonomy.ScopeObservation, error)
	Lease        func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision, func(context.Context) error) error
	Dial         func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error)
	BaselineDial func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error)
	Now          func() time.Time // trusted local owner clock; nil uses real time
}

func (r DomainPolicyTCPRuntime) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (p *DomainPolicy) validTCPFlow(flow DomainPolicyTCPFlow) bool {
	return p != nil && flow.Generation == p.generation && len(flow.FlowID) > 0 && len(flow.FlowID) <= 256 && !strings.ContainsAny(flow.FlowID, "\x00\r\n") && flow.Source.IsValid() && flow.Source.Port() != 0 && flow.Source.Addr().Is4() && flow.Source.Addr() == flow.Client.Address && flow.Destination.IsValid() && flow.Destination.Addr().Is4() && flow.Destination.Addr().IsGlobalUnicast() && !flow.Destination.Addr().IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(flow.Destination.Addr()) && !netip.MustParsePrefix("198.18.0.0/15").Contains(flow.Destination.Addr()) && (flow.Destination.Port() == 80 || flow.Destination.Port() == 443)
}

// HandleTCP is an actual pre-outbound consumer: it reads this connection's
// bytes, decides once, dials only the chosen route and forwards the same bytes.
// It consumes and closes the admitted connection on every outcome. Captured
// excluded/unknown clients never get sniffed or opened as an owned outbound.
func (p *DomainPolicy) HandleTCP(ctx context.Context, conn net.Conn, flow DomainPolicyTCPFlow, runtime DomainPolicyTCPRuntime) (DomainPolicyDecision, error) {
	d := DomainPolicyDecision{Kind: "refused", Reason: "FLOW_AUTHORITY_UNAVAILABLE"}
	if conn != nil {
		defer conn.Close()
	}
	if !p.validTCPFlow(flow) || conn == nil || runtime.Guard == nil || runtime.Lease == nil || runtime.Dial == nil || !runtime.Limits.valid() {
		return d, ErrDomainPolicy
	}
	d.Generation = p.generation
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	scope, err := runtime.Guard(ctx, flow)
	if err = errors.Join(err, ctx.Err()); err != nil {
		return d, err
	}
	question := DomainPolicyFlow{Client: flow.Client, Destination: flow.Destination.Addr(), Protocol: "tcp", DefaultCoverage: flow.DefaultCoverage, Coalesced: flow.Coalesced}
	gate := p.DecideWithScope(question, scope, runtime.now())
	if gate.Kind == "outside" {
		return gate, nil
	}
	if gate.Reason == "SCOPE_UNAVAILABLE" || gate.Reason == "SCOPE_IDENTITY_CHANGED" || gate.Reason == "POLICY_INVALID" {
		return gate, ErrDomainPolicy
	}
	evidence, prefix, err := sniffDomainPolicyTCP(ctx, conn, runtime.Limits)
	if err != nil {
		d.Reason = "NAME_READ_FAILED"
		return d, err
	}
	question.Name, question.NameSource, question.NameState = evidence.Name, evidence.Source, evidence.State
	question.BeforeOutbound = true
	scope, err = runtime.Guard(ctx, flow)
	if err = errors.Join(err, ctx.Err()); err != nil {
		return d, err
	}
	d = p.DecideWithScope(question, scope, runtime.now())
	if d.Kind == "outside" {
		return d, nil
	}
	if d.Kind != "default" && d.Kind != "service" && d.Kind != "baseline" {
		return d, ErrDomainPolicy
	}
	dial := runtime.Dial
	if d.Kind == "baseline" {
		if runtime.BaselineDial == nil {
			d.Kind, d.Reason = "refused", "BASELINE_FLOW_GRANT_REQUIRED"
			return d, ErrDomainPolicy
		}
		dial = runtime.BaselineDial
	}
	var leaseMu sync.Mutex
	leaseOpen, entered, misuse := true, false, false
	forwardDone := make(chan struct{})
	var forwardErr error
	leaseErr := runtime.Lease(ctx, flow, d, func(leaseCtx context.Context) error {
		leaseMu.Lock()
		if leaseCtx == nil || !leaseOpen || entered {
			misuse = true
			leaseMu.Unlock()
			return ErrDomainPolicy
		}
		entered = true
		leaseMu.Unlock()
		defer close(forwardDone)
		// The outer Stop/control lifetime remains authoritative even if an
		// owner accidentally supplies a less restrictive lease context.
		forwardCtx, cancel := context.WithCancel(leaseCtx)
		defer cancel()
		stopParent := context.AfterFunc(ctx, cancel)
		defer stopParent()
		if ctx.Err() != nil {
			cancel()
		}
		forwardErr = p.forwardTCP(forwardCtx, conn, flow, question, d, prefix, runtime, dial)
		return forwardErr
	})
	leaseMu.Lock()
	leaseOpen = false
	didEnter := entered
	leaseMu.Unlock()
	if didEnter {
		<-forwardDone // an asynchronous owner still cannot return an unjoined flow
	}
	leaseMu.Lock()
	badLease := misuse
	leaseMu.Unlock()
	if !didEnter || badLease || leaseErr != nil || forwardErr != nil {
		d.Kind, d.Reason = "failed", "OUTBOUND_EXECUTION_FAILED"
		return d, errors.Join(leaseErr, forwardErr, ErrDomainPolicy)
	}
	return d, nil
}

func (p *DomainPolicy) forwardTCP(ctx context.Context, conn net.Conn, flow DomainPolicyTCPFlow, question DomainPolicyFlow, decision DomainPolicyDecision, prefix []byte, runtime DomainPolicyTCPRuntime, dial func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error)) error {
	// A fresh decision at the real dial boundary closes expiry/identity gaps.
	check := func() error {
		scope, err := runtime.Guard(ctx, flow)
		if err = errors.Join(err, ctx.Err()); err != nil {
			return err
		}
		current := p.DecideWithScope(question, scope, runtime.now())
		if current.Generation != decision.Generation || current.Kind != decision.Kind || current.Route != decision.Route || current.ServiceID != decision.ServiceID || current.Reason != decision.Reason {
			return ErrDomainPolicy
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	outbound, err := dial(ctx, flow, decision)
	if err != nil || outbound == nil {
		if outbound != nil {
			_ = outbound.Close()
		}
		return errors.Join(err, ErrDomainPolicy)
	}
	defer outbound.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = outbound.Close() })
	defer stop()
	if err := check(); err != nil {
		return err
	}
	// Every byte consumed by sniffing, including any already-read body/early
	// data, is replayed exactly once. Original IP/port never changes to a name.
	return relayDomainPolicyTCP(ctx, conn, outbound, prefix)
}

func relayDomainPolicyTCP(ctx context.Context, inbound, outbound net.Conn, prefix []byte) error {
	upDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(outbound, io.MultiReader(bytes.NewReader(prefix), inbound))
		if half, ok := outbound.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, half.CloseWrite())
		} else {
			_ = outbound.Close()
		}
		upDone <- err
	}()
	_, downErr := io.Copy(inbound, outbound)
	if half, ok := inbound.(interface{ CloseWrite() error }); ok && downErr == nil {
		_ = half.CloseWrite()
	}
	// Join the upstream worker even on remote failure or Stop. This handler
	// must not return a drained lease with an untracked blocked reader.
	_ = inbound.Close()
	_ = outbound.Close()
	upErr := <-upDone
	return errors.Join(ctx.Err(), downErr, upErr)
}
