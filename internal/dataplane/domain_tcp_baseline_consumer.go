package dataplane

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type domainTCPBaselineConn struct {
	self     *domainTCPBaselineConn
	resource *domainTCPBaselineExecutionResource
	native   *domainTCPBaselineNative
	conn     net.Conn
	ctx      context.Context
	stop     func() bool
	mu       sync.Mutex
	closed   bool
	err      error
}

// Called only by the original capture coordinator inside its synchronous
// admitted lease. Original accepted FD -> durable BF intent -> COMMON -> native
// transparent Connect -> closing proof all precede the first application byte.
func dialDomainTCPBaseline(ctx context.Context, kernel *domainTCPBaselineKernelOwner, socket DomainPolicyTCPSocket, flow DomainPolicyTCPFlow, decision DomainPolicyDecision) (net.Conn, error) {
	defer domainTCPMeasure("baseline-dial")(0)
	if ctx == nil || kernel == nil || flow.synthetic == nil || !flow.synthetic.matches(flow) || flow.Source != socket.Source || flow.Destination != socket.OriginalDestination || decision.Kind != "baseline" || decision.Generation != flow.Generation {
		return nil, ErrDomainTCPBaselineKernel
	}
	r, err := issueDomainTCPBaselineFlow(ctx, kernel, socket)
	if r == nil {
		return nil, err
	}
	if err == nil {
		err = r.prepare(ctx)
	}
	var native *domainTCPBaselineNative
	if err == nil {
		native, err = r.connectNative(ctx)
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, r.retire(cleanup))
	}
	conn := native.connection()
	if conn == nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return nil, errors.Join(ErrDomainTCPBaselineKernel, r.retire(cleanup))
	}
	c := &domainTCPBaselineConn{resource: r, native: native, conn: conn, ctx: ctx}
	c.self = c
	c.watchCancellation()
	return c, nil
}

func (c *domainTCPBaselineConn) watchCancellation() {
	// A pre-cancelled context can invoke Close before AfterFunc returns. Hold
	// the SAME close mutex until the stop function itself has been published.
	c.mu.Lock()
	c.stop = context.AfterFunc(c.ctx, func() { _ = c.Close() })
	c.mu.Unlock()
}

func (c *domainTCPBaselineConn) current() error {
	if c == nil || c.self != c || c.conn == nil || c.ctx == nil {
		return ErrDomainTCPBaselineKernel
	}
	return c.ctx.Err()
}
func (c *domainTCPBaselineConn) Read(b []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	return c.conn.Read(b)
}
func (c *domainTCPBaselineConn) Write(b []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	return c.conn.Write(b)
}
func (c *domainTCPBaselineConn) CloseWrite() error {
	if err := c.current(); err != nil {
		return err
	}
	half, ok := c.conn.(interface{ CloseWrite() error })
	if !ok {
		return ErrDomainTCPBaselineKernel
	}
	return half.CloseWrite()
}
func (c *domainTCPBaselineConn) LocalAddr() net.Addr {
	if c == nil || c.self != c {
		return nil
	}
	return c.conn.LocalAddr()
}
func (c *domainTCPBaselineConn) RemoteAddr() net.Addr {
	if c == nil || c.self != c {
		return nil
	}
	return c.conn.RemoteAddr()
}
func (c *domainTCPBaselineConn) SetDeadline(t time.Time) error {
	if err := c.current(); err != nil {
		return err
	}
	return c.conn.SetDeadline(t)
}
func (c *domainTCPBaselineConn) SetReadDeadline(t time.Time) error {
	if err := c.current(); err != nil {
		return err
	}
	return c.conn.SetReadDeadline(t)
}
func (c *domainTCPBaselineConn) SetWriteDeadline(t time.Time) error {
	if err := c.current(); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}
func (c *domainTCPBaselineConn) Close() error {
	if c == nil || c.self != c {
		return ErrDomainTCPBaselineKernel
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.err
	}
	c.closed = true
	if c.stop != nil {
		c.stop()
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), 5*time.Second)
	defer cancel()
	c.err = errors.Join(c.native.closeNative(), c.resource.retire(cleanup))
	return c.err
}
