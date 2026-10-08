package dnscontrol

import (
	"context"
	"net"
	"net/netip"
)

// The common owner holds the exact current Stop/generation/device/gate lease
// through the synchronous send. This callback is execution authority, not a
// boolean capability or a permission cached at Resolve time.
type NetworkPolicyDNSPublisher func(context.Context, NetworkPolicyDNSAdmission, func() error) error

// Serve reuses NET's existing bounded listener, workers and framed TCP/UDP
// lifecycle. Physical INPUT/DNAT leases and exact old-flow settlement remain
// with the same Manager adapter; this library never changes the firewall.
func (r *NetworkPolicyDNSResolver) Serve(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener, publish NetworkPolicyDNSPublisher) error {
	if r == nil || publish == nil {
		return ErrNetworkPolicyDNS
	}
	if r.service != nil {
		defer r.service.cache.clear()
	}
	return ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
		Admit: func(ctx context.Context, client netip.Addr) error { _, err := r.admission(ctx, client, ""); return err },
		Exchange: func(ctx context.Context, client netip.Addr, query []byte, send func([]byte) error) error {
			return r.Publish(ctx, client, query, publish, send)
		},
	})
}
