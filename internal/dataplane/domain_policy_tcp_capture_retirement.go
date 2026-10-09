package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

var ErrDomainPolicyTCPCaptureRetirementPending = errors.New("original TCP capture has not completed all consumer joins")

// Retained only from the SAME emitted capture before retirement. Terminal
// observation does not authorize DNS-cache expiry, conntrack deletion, listener
// replacement or standby removal; those owners must verify their own facts.
type DomainPolicyTCPCaptureRetirement struct {
	self     *DomainPolicyTCPCaptureRetirement
	capture  *DomainPolicyTCPCapture
	endpoint netip.AddrPort
	done     chan struct{}
	once     sync.Once
	result   error
}

func (*DomainPolicyTCPCaptureRetirement) String() string { return "[original TCP capture retirement]" }
func (*DomainPolicyTCPCaptureRetirement) GoString() string {
	return "[original TCP capture retirement]"
}

func newDomainPolicyTCPCaptureRetirement(c *DomainPolicyTCPCapture) *DomainPolicyTCPCaptureRetirement {
	r := &DomainPolicyTCPCaptureRetirement{capture: c, endpoint: c.listener.Addr().(*net.TCPAddr).AddrPort(), done: make(chan struct{})}
	r.self = r
	return r
}

func captureRetirementContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

// Retirement supplies an original carrier, never a terminal DTO. Closing the
// capture alone cannot publish completion while early handler frames remain.
func (c *DomainPolicyTCPCapture) Retirement(ctx context.Context) (*DomainPolicyTCPCaptureRetirement, error) {
	if c == nil || c.self != c || captureRetirementContext(ctx) != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := c.Current(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.retirement
	if c.closed || r == nil || r.self != r || r.capture != c || r.endpoint != c.spec.Listen {
		return nil, ErrDomainPolicyTCPConsumer
	}
	return r, nil
}

// Joined is a fresh finite read of the original terminal carrier. Original
// forward cancellation is expected during retirement; caller cleanup admission
// belongs to NET/CORE and cannot be reconstructed from this comparison.
func (r *DomainPolicyTCPCaptureRetirement) Joined(ctx context.Context) error {
	if r == nil || r.self != r || captureRetirementContext(ctx) != nil || r.capture == nil || r.capture.self != r.capture || r.capture.retirement != r {
		return ErrDomainPolicyTCPConsumer
	}
	select {
	case <-r.done:
	default:
		return ErrDomainPolicyTCPCaptureRetirementPending
	}
	c := r.capture
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	select {
	case <-c.closeDone:
	default:
		return ErrDomainPolicyTCPCaptureRetirementPending
	}
	if !closed || r.endpoint != c.spec.Listen {
		return ErrDomainPolicyTCPConsumer
	}
	return errors.Join(r.result, ctx.Err())
}

// Endpoint returns terminal comparison data from the actual opened listener.
// It cannot turn a candidate conntrack tuple into an original accepted flow ID.
func (r *DomainPolicyTCPCaptureRetirement) Endpoint(ctx context.Context) (netip.AddrPort, error) {
	if err := r.Joined(ctx); err != nil {
		return netip.AddrPort{}, err
	}
	return r.endpoint, nil
}

// ONLY the actual serveDomainPolicyTCPCapture return defer calls this producer,
// after domainPolicyTCPSynchronousScope joined every original handler frame.
// capture.Close then joins all preparation/mapping flows/watchers before done.
func (c *DomainPolicyTCPCapture) completeRetirement() {
	if c == nil || c.self != c || c.retirement == nil || c.retirement.self != c.retirement || c.retirement.capture != c {
		return
	}
	r := c.retirement
	r.once.Do(func() {
		r.result = c.Close()
		close(r.done)
	})
}
