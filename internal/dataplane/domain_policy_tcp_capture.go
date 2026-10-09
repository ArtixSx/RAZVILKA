package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

var ErrDomainPolicyTCPConsumer = errors.New("original synthetic TCP capture/transition consumer is unavailable")

var domainPolicyTCPSyntheticPool = netip.MustParsePrefix("198.18.0.0/15")

func domainPolicyTCPPublicIPv4(ip netip.Addr) bool {
	return ip.Is4() && publicfetch.PublicAddress(ip)
}

// Intent and observations below grant no kernel/process permission. The
// original Manager/NET owner must provide the live interfaces, not a JSON
// receipt, reconstructed tuple, DNS observation or caller-provided Ready flag.
type DomainPolicyTCPCaptureSpec struct {
	Xray   DomainPolicyTCPXraySpec
	Client autonomy.ClientPacket
	Listen netip.AddrPort
	Limits DomainPolicySniffLimits
}

type DomainPolicyTCPSocket struct {
	Source, OriginalDestination, Listener netip.AddrPort
}

// Comparison image returned by the original flow owner. It cannot construct
// NET's original DNS mapping or its prepared transition/capture handle. The
// shared production coordinator must bind those original objects separately;
// no implementation or publication capability is installed by this leaf.
type DomainPolicyTCPSyntheticMapping struct {
	Generation, PublicationID, Name, ServiceID, NodeID string
	Client                                             autonomy.ClientPacket
	SyntheticIP, RealIP                                netip.Addr
	ExpiresAt                                          time.Time
}

// Guard verifies the retained ORIGINAL source, capture selector, immutable
// mapping, prepared source-specific baseline transition, current control and
// exclusion generation. WithFlow enters once under that owner's revocable
// lease and joins the callback before returning. Stop/exclusion must cancel
// and join these leases before retiring Xray; NET retains the standby DNAT
// until its separate cache/conntrack settlement proves cleanup permissible.
type DomainPolicyTCPFlowLease interface {
	Binding() (DomainPolicyTCPSyntheticMapping, string)
	Guard(context.Context, DomainPolicyTCPSocket) (autonomy.ScopeObservation, error)
	WithFlow(context.Context, DomainPolicyTCPSocket, func(context.Context) error) error
}

// WithCapture registers the actual listener in the SAME Manager inventory,
// prepares INPUT/capture and baseline transition dependencies, then consumes
// synchronously. It cannot publish DNS merely from listener readiness. AdmitTCP
// binds the actual accepted tuple to the original MAC/iif and transition owner.
// No production implementation is inferred when that integration is absent.
type DomainPolicyTCPCaptureOwner interface {
	WithCapture(context.Context, DomainPolicyTCPCaptureSpec, netip.AddrPort, func(context.Context) error) error
	AdmitTCP(context.Context, DomainPolicyTCPSocket) (DomainPolicyTCPFlowLease, error)
}

type DomainPolicyTCPExecutionOwner interface {
	DomainPolicyTCPCaptureOwner
	DomainPolicyTCPXrayOwner
}

// RunDomainPolicyTCP is an executable leaf of the existing Xray adapter. The
// original Manager owns its lifecycle; this creates no manager or journal.
// Missing original capture/transition/process integration refuses explicitly.
func (a *ProxyTunnelAdapter) RunDomainPolicyTCP(ctx context.Context, policy *DomainPolicy, spec DomainPolicyTCPCaptureSpec, owner DomainPolicyTCPExecutionOwner) error {
	if ctx == nil || policy == nil || owner == nil || spec.Xray.Generation != policy.generation || !spec.valid() || !domainPolicyTCPCaptureSupported() {
		return ErrDomainPolicyTCPConsumer
	}
	return a.WithDomainPolicyTCPXray(ctx, spec.Xray, owner, func(runtimeCtx context.Context, xray *DomainPolicyTCPXray) error {
		return policy.serveDomainPolicyTCPCapture(runtimeCtx, spec, owner, xray)
	})
}

func (s DomainPolicyTCPCaptureSpec) valid() bool {
	mac, err := net.ParseMAC(s.Client.MAC)
	return s.Xray.valid() && s.Limits.valid() && s.Client.Address.Is4() && s.Client.Address.IsGlobalUnicast() &&
		len(mac) == 6 && err == nil && strings.ToLower(mac.String()) == s.Client.MAC && mac[0]&1 == 0 &&
		proxyFirewallInterface.MatchString(s.Client.Interface) && s.Client.Interface != "lo" && s.Client.SegmentID != "" &&
		s.Listen.IsValid() && s.Listen.Port() != 0 && s.Listen.Addr().Is4() && s.Listen.Addr().IsGlobalUnicast() && !s.Listen.Addr().IsLoopback()
}

func (p *DomainPolicy) serveDomainPolicyTCPCapture(ctx context.Context, spec DomainPolicyTCPCaptureSpec, owner DomainPolicyTCPCaptureOwner, xray *DomainPolicyTCPXray) error {
	if !domainPolicyTCPCaptureSupported() {
		return ErrDomainPolicyTCPConsumer
	}
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(spec.Listen))
	if err != nil {
		return err
	}
	defer listener.Close()
	return domainPolicyTCPSynchronousScope(ctx, func(consume func(context.Context) error) error {
		return owner.WithCapture(ctx, spec, listener.Addr().(*net.TCPAddr).AddrPort(), consume)
	}, func(captureCtx context.Context) error {
		if captureCtx == nil {
			return ErrDomainPolicyTCPConsumer
		}
		// Parent lifetime remains authoritative even if an owner supplies a
		// wider context. Joining all handlers precedes the process retirement.
		flowCtx, cancel := context.WithCancel(captureCtx)
		defer cancel()
		stopParent := context.AfterFunc(ctx, cancel)
		defer stopParent()
		if ctx.Err() != nil {
			cancel()
		}
		stop := context.AfterFunc(flowCtx, func() { _ = listener.Close() })
		defer stop()
		var flows sync.WaitGroup
		defer func() { cancel(); _ = listener.Close(); flows.Wait() }()
		// Admission is bounded before sniffing; malicious half-open streams
		// cannot accumulate an unbounded worker per accepted connection.
		capacity := make(chan struct{}, 32)
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				cancel()
				return errors.Join(err, flowCtx.Err())
			}
			select {
			case capacity <- struct{}{}:
				flows.Add(1)
				go func() {
					defer flows.Done()
					defer func() { <-capacity }()
					_, _ = p.handleCapturedDomainPolicyTCP(flowCtx, conn, spec, owner, xray, observeDomainPolicyTCPSocket)
				}()
			default:
				_ = conn.Close()
			}
		}
	})
}

// The original owner's callback is a lifetime, not an escapable constructor.
// Refuse missing/double/deferred entry and cancel+join an asynchronous entry
// before returning to a caller that may retire its registration dependencies.
func domainPolicyTCPSynchronousScope(parent context.Context, with func(func(context.Context) error) error, consume func(context.Context) error) error {
	var mu sync.Mutex
	open, entered, misuse := true, false, false
	var cancel context.CancelFunc
	var consumed error
	done := make(chan struct{})
	err := with(func(ownerCtx context.Context) error {
		mu.Lock()
		if !open || entered || ownerCtx == nil {
			misuse = true
			mu.Unlock()
			return ErrDomainPolicyTCPConsumer
		}
		entered = true
		ctx, revoke := context.WithCancel(ownerCtx)
		cancel = revoke
		mu.Unlock()
		defer close(done)
		defer revoke()
		stop := context.AfterFunc(parent, revoke)
		defer stop()
		if parent.Err() != nil {
			revoke()
		}
		consumed = consume(ctx)
		return consumed
	})
	mu.Lock()
	open = false
	didEnter, revoke := entered, cancel
	mu.Unlock()
	if didEnter {
		select {
		case <-done:
		default:
			mu.Lock()
			misuse = true
			mu.Unlock()
			revoke()
			<-done
		}
	}
	mu.Lock()
	bad := misuse
	mu.Unlock()
	if !didEnter || bad {
		return errors.Join(err, consumed, ErrDomainPolicyTCPConsumer)
	}
	return errors.Join(err, consumed)
}

// observe is private and injected only by socket-model tests. Production uses
// the accepted *net.TCPConn's native SO_ORIGINAL_DST and actual RemoteAddr.
func (p *DomainPolicy) handleCapturedDomainPolicyTCP(ctx context.Context, conn *net.TCPConn, spec DomainPolicyTCPCaptureSpec, owner DomainPolicyTCPCaptureOwner, xray *DomainPolicyTCPXray, observe func(*net.TCPConn) (DomainPolicyTCPSocket, error)) (DomainPolicyDecision, error) {
	refused := DomainPolicyDecision{Kind: "refused", Reason: "SYNTHETIC_CAPTURE_AUTHORITY_REQUIRED"}
	if conn == nil {
		return refused, ErrDomainPolicyTCPConsumer
	}
	defer conn.Close()
	if owner == nil || xray == nil || observe == nil || ctx == nil || ctx.Err() != nil {
		return refused, ErrDomainPolicyTCPConsumer
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	socket, err := observe(conn)
	if err != nil || socket.Listener != spec.Listen || socket.Source.Addr() != spec.Client.Address || !domainPolicyTCPSyntheticPool.Contains(socket.OriginalDestination.Addr()) ||
		!socket.Source.IsValid() || socket.Source.Port() == 0 || (socket.OriginalDestination.Port() != 80 && socket.OriginalDestination.Port() != 443) {
		return refused, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	lease, err := owner.AdmitTCP(ctx, socket)
	if err != nil || lease == nil {
		return refused, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	mapping, flowID := lease.Binding()
	binding := &domainPolicyTCPSyntheticBinding{mapping: mapping, socket: socket, spec: spec.Xray}
	flow := DomainPolicyTCPFlow{Generation: mapping.Generation, FlowID: flowID, Source: socket.Source, Destination: socket.OriginalDestination, Client: mapping.Client, synthetic: binding}
	if mapping.Client != spec.Client || !p.validTCPFlow(flow) || !time.Now().Before(mapping.ExpiresAt) || !xray.matches(spec.Xray) {
		return refused, ErrDomainPolicyTCPConsumer
	}
	runtime := DomainPolicyTCPRuntime{
		Limits: spec.Limits,
		Guard: func(c context.Context, f DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
			current, id := lease.Binding()
			if current != mapping || id != flowID || !binding.matches(f) || !time.Now().Before(mapping.ExpiresAt) {
				return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
			}
			return lease.Guard(c, socket)
		},
		Lease: func(c context.Context, _ DomainPolicyTCPFlow, _ DomainPolicyDecision, forward func(context.Context) error) error {
			return lease.WithFlow(c, socket, forward)
		},
		Dial: xray.dial,
	}
	return p.HandleTCP(ctx, conn, flow, runtime)
}

type domainPolicyTCPSyntheticBinding struct {
	mapping DomainPolicyTCPSyntheticMapping
	socket  DomainPolicyTCPSocket
	spec    DomainPolicyTCPXraySpec
}

func (b *domainPolicyTCPSyntheticBinding) matches(f DomainPolicyTCPFlow) bool {
	if b == nil {
		return false
	}
	m := b.mapping
	name, err := config.PolicyDomain(m.Name)
	return err == nil && name == m.Name && m.PublicationID != "" && len(m.PublicationID) <= 256 && !strings.ContainsAny(m.PublicationID, "\x00\r\n") &&
		f.Source == b.socket.Source && f.Destination == b.socket.OriginalDestination && f.Client == m.Client && m.Client.Address == f.Source.Addr() &&
		f.Generation == m.Generation && m.Generation == b.spec.Generation && m.Name == b.spec.Name && m.ServiceID == b.spec.ServiceID && m.NodeID == b.spec.NodeID &&
		m.RealIP == b.spec.RealIP && domainPolicyTCPPublicIPv4(m.RealIP) && m.SyntheticIP == f.Destination.Addr() && domainPolicyTCPSyntheticPool.Contains(m.SyntheticIP) && !m.ExpiresAt.IsZero()
}

func (b *domainPolicyTCPSyntheticBinding) acceptsDecision(d DomainPolicyDecision) bool {
	return b != nil && d.Generation == b.mapping.Generation && d.Kind == "service" && d.ServiceID == b.mapping.ServiceID && d.Route == "xray:"+b.mapping.NodeID
}
