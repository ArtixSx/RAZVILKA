package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Only the original protected policy runner implements the production reader.
// A route observation is not permission: the complete original kernel and
// packet-program contract is checked before and after this local lookup.
type domainTCPDirectRouteReader interface {
	ReadDomainTCPDirectRoute(context.Context, netip.Addr, netip.Addr) ([]byte, error)
}

var errDomainTCPDirectReadOnlyContext = errors.New("router DIRECT cannot consume cleanup or read-only authority")

func domainTCPDirectForwardContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrDomainTCPBaselineKernel
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrDomainTCPBaselineKernel
	}
	if ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil || ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPGuardReadKey{}) != nil {
		return errors.Join(ErrDomainTCPBaselineKernel, errDomainTCPDirectReadOnlyContext)
	}
	return nil
}

type domainTCPDirectScope struct {
	self     *domainTCPDirectScope
	owner    *DomainTCPOriginalScope
	kernel   *domainTCPBaselineKernelOwner
	accepted *domainAcceptedTCP
	flow     DomainPolicyTCPFlow
	path     domainTCPBaselinePath
	source   netip.Addr
	target   netip.AddrPort
}

func (d *domainTCPDirectScope) registered(ctx context.Context) error {
	if err := domainTCPDirectForwardContext(ctx); err != nil {
		return err
	}
	if d == nil || d.self != d || ctx == nil || ctx.Err() != nil || d.owner == nil || d.owner.self != d.owner || d.kernel == nil || d.kernel.self != d.kernel || d.kernel.capture == nil || d.kernel.capture.process == nil || d.kernel.path != d.path || d.kernel.flow.Load() != nil {
		return ErrDomainTCPBaselineKernel
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrDomainTCPBaselineKernel
	}
	c := d.kernel.capture
	o := d.owner
	o.mu.Lock()
	ok := !o.closed && o.kernel == d.kernel && o.captureResource == c && o.capture == c.capture && o.process == c.process && o.baseline == d.kernel.baseline && o.prepared != nil && o.prepared.self == o.prepared && o.prepared.source == c.mapping
	o.mu.Unlock()
	if !ok || d.accepted == nil || d.accepted.current(ctx, c.capture, d.accepted.socket) != nil || c.capture.directFailure() != nil {
		return ErrDomainTCPBaselineKernel
	}
	s := c.process.scope
	if s == nil {
		return ErrDomainTCPBaselineKernel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || !s.domainTCPProof || s.domainTCPOwner != o || s.syntheticClosing || s.failure != nil || s.execution == nil || s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return ErrDomainTCPBaselineKernel
	}
	// Legacy unknown/pending BF effects remain an independent recovery fence.
	for _, prior := range s.execution.Resources {
		if prior.DomainTCPBaseline != nil && prior.State != "removed" && prior.State != "unused" {
			return ErrDomainTCPBaselineKernel
		}
	}
	return nil
}

func (d *domainTCPDirectScope) current(ctx context.Context) error {
	if err := d.registered(ctx); err != nil {
		return err
	}
	if err := d.kernel.guardFlow(ctx, d.flow); err != nil {
		return err
	}
	return d.registered(ctx)
}

func dialDomainTCPDirect(ctx context.Context, owner *DomainTCPOriginalScope, kernel *domainTCPBaselineKernelOwner, socket DomainPolicyTCPSocket, flow DomainPolicyTCPFlow, decision DomainPolicyDecision) (net.Conn, error) {
	if err := domainTCPDirectForwardContext(ctx); err != nil {
		return nil, err
	}
	if ctx == nil || kernel == nil || kernel.capture == nil || flow.synthetic == nil || !flow.synthetic.matches(flow) || flow.Source != socket.Source || flow.Destination != socket.OriginalDestination || decision.Kind != "baseline" || decision.Generation != flow.Generation {
		return nil, ErrDomainTCPBaselineKernel
	}
	accepted, err := originalDomainAcceptedTCP(ctx, kernel.capture.capture, socket)
	if err != nil {
		return nil, err
	}
	d := &domainTCPDirectScope{owner: owner, kernel: kernel, accepted: accepted, flow: flow, path: kernel.path, target: netip.AddrPortFrom(kernel.capture.definition.Process.Capture.Xray.RealIP, socket.OriginalDestination.Port())}
	d.self = d
	if err := d.registered(ctx); err != nil {
		return nil, err
	}
	return d.connect(ctx)
}

// Strict local-output route equivalence is additional to the complete
// forwarded-route/standard-RPDB/ACCEPT-only/no-NAT packet proof. No L4/UID
// lookup capability is inferred from old iproute2 or from this JSON.
func domainTCPDirectRouteMatches(raw []byte, source netip.Addr, target netip.AddrPort, path domainTCPBaselinePath) error {
	if len(raw) == 0 || len(raw) > 2<<20 || nfqws2ManagedUniqueJSON(raw) != nil {
		return ErrDomainTCPBaselineKernel
	}
	var routes []struct {
		Type            string          `json:"type,omitempty"`
		Destination     string          `json:"dst"`
		Source          string          `json:"from"`
		PreferredSource string          `json:"prefsrc,omitempty"`
		Gateway         string          `json:"gateway,omitempty"`
		Device          string          `json:"dev"`
		Table           json.RawMessage `json:"table,omitempty"`
		Flags           []string        `json:"flags,omitempty"`
		Cache           json.RawMessage `json:"cache,omitempty"`
		UID             *int            `json:"uid,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&routes) != nil || decoder.Decode(new(any)) != io.EOF || len(routes) != 1 {
		return ErrDomainTCPBaselineKernel
	}
	r := routes[0]
	if r.Type != "" && r.Type != "unicast" || r.Destination != target.Addr().String() || r.Source != source.String() || r.PreferredSource != "" && r.PreferredSource != source.String() || r.Device != path.Egress || len(r.Flags) != 0 || r.UID != nil && *r.UID != 0 || len(r.Cache) != 0 && !bytes.Equal(r.Cache, []byte("[]")) || len(r.Table) != 0 && !bytes.Equal(r.Table, []byte(`"main"`)) && !bytes.Equal(r.Table, []byte(`254`)) {
		return ErrDomainTCPBaselineKernel
	}
	wantGateway := ""
	if path.Gateway.IsValid() {
		wantGateway = path.Gateway.String()
	}
	if r.Gateway != wantGateway {
		return ErrDomainTCPBaselineKernel
	}
	return nil
}

// In-memory ownership lasts exactly through the joined handler. No durable BF
// permission or packet rule is created. Close failures stay in capture's
// retirement result even when a relay ignores a socket Close return value.
type domainTCPDirectConn struct {
	conn         net.Conn
	self         *domainTCPDirectConn
	capture      *DomainPolicyTCPCapture
	ctx          context.Context
	once         sync.Once
	joinOnce     sync.Once
	closeOwned   func() error
	err          error
	stop         func() bool
	callbackDone chan struct{}
}

func (c *domainTCPDirectConn) current() error {
	if c == nil || c.self != c || c.ctx == nil || c.conn == nil {
		return ErrDomainTCPBaselineKernel
	}
	return c.ctx.Err()
}

func (c *domainTCPDirectConn) closeLocal() {
	c.once.Do(func() { c.err = c.closeOwned(); c.capture.recordDirectFailure(c.err) })
}
func (c *domainTCPDirectConn) Close() error {
	if c == nil || c.self != c || c.closeOwned == nil {
		return ErrDomainTCPBaselineKernel
	}
	c.closeLocal()
	c.joinOnce.Do(func() {
		if c.stop != nil && !c.stop() {
			<-c.callbackDone
		}
	})
	return c.err
}
func (c *domainTCPDirectConn) Read(b []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	return c.conn.Read(b)
}
func (c *domainTCPDirectConn) Write(b []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	return c.conn.Write(b)
}
func (c *domainTCPDirectConn) CloseWrite() error {
	if err := c.current(); err != nil {
		return err
	}
	if tcp, ok := c.conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return ErrDomainTCPBaselineKernel
}
func (c *domainTCPDirectConn) LocalAddr() net.Addr {
	if c.current() != nil {
		return nil
	}
	return c.conn.LocalAddr()
}
func (c *domainTCPDirectConn) RemoteAddr() net.Addr {
	if c.current() != nil {
		return nil
	}
	return c.conn.RemoteAddr()
}
func (c *domainTCPDirectConn) SetDeadline(t time.Time) error {
	if err := c.current(); err != nil {
		return err
	}
	return c.conn.SetDeadline(t)
}
func (c *domainTCPDirectConn) SetReadDeadline(t time.Time) error {
	if err := c.current(); err != nil {
		return err
	}
	return c.conn.SetReadDeadline(t)
}
func (c *domainTCPDirectConn) SetWriteDeadline(t time.Time) error {
	if err := c.current(); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *DomainPolicyTCPCapture) recordDirectFailure(err error) {
	if err == nil {
		return
	}
	c.directMu.Lock()
	c.directError = errors.Join(c.directError, err)
	c.directMu.Unlock()
	// Cancel sibling flows; never call Close here (the failing handler is one
	// of the flows that Close must join). Retirement keeps the original error.
	if c.cancel != nil {
		c.cancel()
	}
}
func (c *DomainPolicyTCPCapture) directFailure() error {
	c.directMu.Lock()
	defer c.directMu.Unlock()
	return c.directError
}
