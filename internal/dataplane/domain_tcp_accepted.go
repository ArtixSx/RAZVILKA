package dataplane

import (
	"context"
	"net"
	"sync/atomic"
)

type domainAcceptedTCPKey struct{}

// Only the actual capture handler issues this private, revocable carrier.
// A matching tuple, listener address or conntrack row cannot recreate its FD.
type domainAcceptedTCP struct {
	self    *domainAcceptedTCP
	capture *DomainPolicyTCPCapture
	conn    *net.TCPConn
	socket  DomainPolicyTCPSocket
	open    atomic.Bool
}

func (a *domainAcceptedTCP) current(ctx context.Context, capture *DomainPolicyTCPCapture, socket DomainPolicyTCPSocket) error {
	if a == nil || a.self != a || !a.open.Load() || ctx == nil || ctx.Err() != nil || a.conn == nil || a.capture != capture || capture == nil || capture.self != capture || socket != a.socket {
		return ErrDomainPolicyTCPConsumer
	}
	observed, err := observeDomainPolicyTCPSocket(a.conn)
	if err != nil || observed != socket || !a.open.Load() {
		return ErrDomainPolicyTCPConsumer
	}
	return ctx.Err()
}

func originalDomainAcceptedTCP(ctx context.Context, capture *DomainPolicyTCPCapture, socket DomainPolicyTCPSocket) (*domainAcceptedTCP, error) {
	if ctx == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	a, _ := ctx.Value(domainAcceptedTCPKey{}).(*domainAcceptedTCP)
	if err := a.current(ctx, capture, socket); err != nil {
		return nil, err
	}
	return a, nil
}
