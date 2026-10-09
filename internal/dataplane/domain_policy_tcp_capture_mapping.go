package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Actual opened listener/backend, bound by the original registered capture
// owner. No exported constructor, DTO import or source reconstruction exists.
type DomainPolicyTCPCapture struct {
	self         *DomainPolicyTCPCapture
	policy       *DomainPolicy
	spec         DomainPolicyTCPCaptureSpec
	owner        DomainPolicyTCPCaptureOwner
	xray         *DomainPolicyTCPXray
	listener     *net.TCPListener
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	closed       bool
	mappings     map[*dnscontrol.SyntheticDNSMapping]*DomainPolicyTCPCaptureMapping
	reservations map[*dnscontrol.SyntheticDNSMapping]*domainPolicyTCPCapturePreparation
	preparing    sync.WaitGroup
	closeDone    chan struct{}
	closeErr     error
}

func (*DomainPolicyTCPCapture) String() string   { return "[original synthetic TCP capture]" }
func (*DomainPolicyTCPCapture) GoString() string { return "[original synthetic TCP capture]" }

// Only RunDomainPolicyTCP supplies production intent, already LAN-validated.
// Socket-model tests use a real loopback listener, never a production grant.
func newDomainPolicyTCPCapture(ctx context.Context, p *DomainPolicy, spec DomainPolicyTCPCaptureSpec, owner DomainPolicyTCPCaptureOwner, xray *DomainPolicyTCPXray, listener *net.TCPListener) (*DomainPolicyTCPCapture, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || spec.Xray.Generation != p.generation || owner == nil || !xray.matches(spec.Xray) || listener == nil || listener.Addr().(*net.TCPAddr).AddrPort() != spec.Listen {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := xray.check(ctx); err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	c := &DomainPolicyTCPCapture{policy: p, spec: spec, owner: owner, xray: xray, listener: listener, ctx: life, cancel: cancel, mappings: make(map[*dnscontrol.SyntheticDNSMapping]*DomainPolicyTCPCaptureMapping), reservations: make(map[*dnscontrol.SyntheticDNSMapping]*domainPolicyTCPCapturePreparation), closeDone: make(chan struct{})}
	c.self = c
	return c, nil
}

// Address is an observation of this actual listener, never permission to
// redirect traffic or publish DNS. Current also needs original registration.
func (c *DomainPolicyTCPCapture) Address() (netip.AddrPort, error) {
	if c == nil || c.self != c || c.listener == nil {
		return netip.AddrPort{}, ErrDomainPolicyTCPConsumer
	}
	return c.listener.Addr().(*net.TCPAddr).AddrPort(), nil
}

func (c *DomainPolicyTCPCapture) Current(ctx context.Context) error {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || c.ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return ErrDomainPolicyTCPConsumer
	}
	address, err := c.Address()
	if err != nil || address != c.spec.Listen {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	raw, err := c.listener.SyscallConn()
	if err != nil {
		return err
	}
	if err := raw.Control(func(uintptr) {}); err != nil {
		return err
	}
	if err := c.owner.CheckCapture(ctx, c); err != nil {
		return err
	}
	return errors.Join(c.xray.check(ctx), ctx.Err(), c.ctx.Err())
}

// Prepare does not publish. The concrete original owner must install/read back
// the exact synthetic selector under the SAME inventory, with its prepared
// baseline transition dependency, before this handle can pass Current.
func (c *DomainPolicyTCPCapture) PrepareSyntheticMapping(ctx context.Context, source *dnscontrol.SyntheticDNSMapping) (prepared *DomainPolicyTCPCaptureMapping, result error) {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || c.ctx.Err() != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	observation, err := source.Observation(ctx)
	if err != nil || !c.matchesObservation(observation) {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := c.Current(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrDomainPolicyTCPConsumer
	}
	if existing := c.mappings[source]; existing != nil {
		c.mu.Unlock()
		return existing, existing.Current(ctx)
	}
	if pending := c.reservations[source]; pending != nil {
		c.mu.Unlock()
		select {
		case <-pending.done:
			if pending.err != nil || pending.mapping == nil {
				return nil, errors.Join(pending.err, ErrDomainPolicyTCPConsumer)
			}
			return pending.mapping, pending.mapping.Current(ctx)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, ErrDomainPolicyTCPConsumer
		}
	}
	if len(c.reservations) >= 256 {
		c.mu.Unlock()
		return nil, ErrDomainPolicyTCPConsumer
	}
	pending := &domainPolicyTCPCapturePreparation{done: make(chan struct{})}
	c.reservations[source] = pending
	c.preparing.Add(1)
	c.mu.Unlock()
	defer func() { pending.mapping, pending.err = prepared, result; close(pending.done); c.preparing.Done() }()
	prepareCtx, cancelPreparation := context.WithCancel(ctx)
	defer cancelPreparation()
	stop := context.AfterFunc(c.ctx, cancelPreparation)
	defer stop()
	if c.ctx.Err() != nil {
		cancelPreparation()
	}
	ctx = prepareCtx
	if err := c.owner.PrepareSyntheticCapture(ctx, c, source); err != nil {
		return nil, err
	}
	if err := source.Current(ctx); err != nil {
		return nil, err
	}
	if err := c.Current(ctx); err != nil {
		return nil, err
	}
	if err := c.owner.CurrentSyntheticCapture(ctx, c, source); err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(c.ctx)
	observation.CNAMEChain = slices.Clone(observation.CNAMEChain)
	m := &DomainPolicyTCPCaptureMapping{capture: c, source: source, observation: observation, ctx: life, cancel: cancel, connections: make(map[*net.TCPConn]struct{}), watchDone: make(chan struct{}), closeDone: make(chan struct{})}
	m.self = m
	// Done is revocation only. No observation flag or TTL can grant forwarding.
	go func() {
		defer close(m.watchDone)
		select {
		case <-source.Done():
			cancel()
		case <-life.Done():
		}
	}()
	c.mu.Lock()
	if c.closed || c.mappings[source] != nil {
		existing := c.mappings[source]
		c.mu.Unlock()
		_ = m.Close()
		if existing != nil {
			return existing, existing.Current(ctx)
		}
		return nil, ErrDomainPolicyTCPConsumer
	}
	c.mappings[source] = m
	c.mu.Unlock()
	if err := m.Current(ctx); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

type domainPolicyTCPCapturePreparation struct {
	done    chan struct{}
	mapping *DomainPolicyTCPCaptureMapping
	err     error
}

func (c *DomainPolicyTCPCapture) matchesObservation(o dnscontrol.SyntheticDNSMappingObservation) bool {
	s := c.spec
	return o.Authority.Generation == s.Xray.Generation && o.PublicationID != "" && o.Client == s.Client.Address && o.DeviceID == s.DeviceID && o.MAC == s.Client.MAC && o.Ingress == s.Client.Interface && o.QName == s.Xray.Name &&
		o.RealIPv4 == s.Xray.RealIP && domainPolicyTCPPublicIPv4(o.RealIPv4) && domainPolicyTCPSyntheticPool.Contains(o.Synthetic) && !o.ExpiresAt.IsZero()
}

// Close drains this listener's consumers. The common coordinator removes
// active proxy selectors BEFORE Close and retains NET standby DNAT afterwards.
// This is never DNS-cache/conntrack settlement or complete Manager Stop.
func (c *DomainPolicyTCPCapture) Close() error {
	if c == nil || c.self != c {
		return ErrDomainPolicyTCPConsumer
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		<-c.closeDone
		return c.closeErr
	}
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	defer close(c.closeDone)
	_ = c.listener.Close()
	c.preparing.Wait()
	c.mu.Lock()
	mappings := make([]*DomainPolicyTCPCaptureMapping, 0, len(c.mappings))
	for _, mapping := range c.mappings {
		mappings = append(mappings, mapping)
	}
	c.mu.Unlock()
	for _, mapping := range mappings {
		c.closeErr = errors.Join(c.closeErr, mapping.Close())
	}
	return c.closeErr
}

type DomainPolicyTCPCaptureMapping struct {
	self                 *DomainPolicyTCPCaptureMapping
	capture              *DomainPolicyTCPCapture
	source               *dnscontrol.SyntheticDNSMapping
	observation          dnscontrol.SyntheticDNSMappingObservation
	ctx                  context.Context
	cancel               context.CancelFunc
	mu                   sync.Mutex
	closed               bool
	connections          map[*net.TCPConn]struct{}
	flows                sync.WaitGroup
	watchDone, closeDone chan struct{}
}

func (*DomainPolicyTCPCaptureMapping) String() string {
	return "[original prepared synthetic TCP mapping]"
}
func (*DomainPolicyTCPCaptureMapping) GoString() string {
	return "[original prepared synthetic TCP mapping]"
}

func (m *DomainPolicyTCPCaptureMapping) Current(ctx context.Context) error {
	if m == nil || m.self != m || ctx == nil || ctx.Err() != nil || m.ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrDomainPolicyTCPConsumer
	}
	actual, err := m.source.Observation(ctx)
	if err != nil || !m.capture.matchesObservation(actual) || !reflect.DeepEqual(immutableSyntheticTCPObservation(actual), immutableSyntheticTCPObservation(m.observation)) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := m.capture.Current(ctx); err != nil {
		return err
	}
	// This lower original readback MUST NOT call the DNS publication combiner,
	// which calls this Current. NET mapping.Current itself has no such cycle.
	return errors.Join(m.capture.owner.CurrentSyntheticCapture(ctx, m.capture, m.source), ctx.Err(), m.ctx.Err())
}

func immutableSyntheticTCPObservation(o dnscontrol.SyntheticDNSMappingObservation) dnscontrol.SyntheticDNSMappingObservation {
	o.PossiblyIssued = false
	o.LastPossiblyIssuedAt = time.Time{}
	o.LastPossiblyIssuedTTLBound = 0
	return o
}

func (m *DomainPolicyTCPCaptureMapping) flowComparison() domainPolicyTCPSyntheticMapping {
	o, s := m.observation, m.capture.spec
	return domainPolicyTCPSyntheticMapping{Generation: o.Authority.Generation, PublicationID: o.PublicationID, Name: o.QName, ServiceID: s.Xray.ServiceID, NodeID: s.Xray.NodeID, Client: s.Client, SyntheticIP: o.Synthetic, RealIP: o.RealIPv4, ExpiresAt: o.ExpiresAt}
}

func (m *DomainPolicyTCPCaptureMapping) enterFlow(parent context.Context, conn *net.TCPConn) (context.Context, func(), error) {
	if m == nil || m.self != m || parent == nil || parent.Err() != nil || conn == nil {
		return nil, nil, ErrDomainPolicyTCPConsumer
	}
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return nil, nil, ErrDomainPolicyTCPConsumer
	}
	m.flows.Add(1)
	m.connections[conn] = struct{}{}
	m.mu.Unlock()
	// The accepted flow's parent carries current admission/operation values.
	// Capture startup values cannot replace that authority. Mapping lifetime
	// adds revocation and only a stricter deadline to this SAME parent.
	var life context.Context
	var cancel context.CancelFunc
	if deadline, bounded := m.ctx.Deadline(); bounded {
		if parentDeadline, parentBounded := parent.Deadline(); !parentBounded || deadline.Before(parentDeadline) {
			life, cancel = context.WithDeadline(parent, deadline)
		}
	}
	if life == nil {
		life, cancel = context.WithCancel(parent)
	}
	stop := context.AfterFunc(m.ctx, cancel)
	if m.ctx.Err() != nil {
		cancel()
	}
	return life, func() {
		stop()
		cancel()
		_ = conn.Close()
		m.mu.Lock()
		delete(m.connections, conn)
		m.mu.Unlock()
		m.flows.Done()
	}, nil
}

func (m *DomainPolicyTCPCaptureMapping) Close() error {
	if m == nil || m.self != m {
		return ErrDomainPolicyTCPConsumer
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		<-m.closeDone
		return nil
	}
	m.closed = true
	m.cancel()
	connections := make([]*net.TCPConn, 0, len(m.connections))
	for conn := range m.connections {
		connections = append(connections, conn)
	}
	m.mu.Unlock()
	defer close(m.closeDone)
	for _, conn := range connections {
		_ = conn.Close()
	}
	m.flows.Wait()
	<-m.watchDone
	return nil
}
