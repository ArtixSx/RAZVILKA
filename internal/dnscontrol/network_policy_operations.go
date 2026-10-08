package dnscontrol

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const networkPolicyDNSOperationTimeout = 12 * time.Second

// ServeWithOperations uses the SAME existing listener and session lifecycle.
// Each admission and each query obtains a new finite original operation from
// the concrete App Gate. Publish receives that SAME context before resolving,
// so its final leaf cannot accidentally retain the listener's lifetime context.
// The supplied existing publisher still owns durable Stop/device/generation and
// physical gate admission; ExclusiveContext alone grants none of these.
func (r *NetworkPolicyDNSResolver) ServeWithOperations(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener, operations *operationgate.Gate, publish NetworkPolicyDNSPublisher) error {
	if r == nil || ctx == nil || operations == nil || publish == nil {
		return ErrNetworkPolicyDNS
	}
	if r.service != nil {
		defer r.service.cache.clear()
	}
	return ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
		Admit: func(ctx context.Context, client netip.Addr) error {
			bounded, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
			defer cancel()
			held, release, err := operations.ExclusiveContext(bounded)
			if err != nil {
				return err
			}
			defer release()
			_, err = r.admission(held, client, "")
			return err
		},
		Exchange: func(ctx context.Context, client netip.Addr, query []byte, send func([]byte) error) error {
			bounded, cancel := context.WithTimeout(ctx, networkPolicyDNSOperationTimeout)
			defer cancel()
			held, release, err := operations.ExclusiveContext(bounded)
			if err != nil {
				return err
			}
			defer release()
			return r.Publish(held, client, query, publish, send)
		},
	})
}
