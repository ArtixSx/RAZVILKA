package dataplane

import (
	"context"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/nodequality"
)

func (c *ExactNodeChecker) selectEndpoint(ctx context.Context, endpoint exactNodeEndpoint, addresses []netip.Addr) (nodequality.SelectedEndpoint, error) {
	tcp := endpoint.Protocol != "hysteria2" && endpoint.Protocol != "tuic"
	return nodequality.SelectEndpoint(ctx, addresses, tcp, func(ctx context.Context, address netip.Addr) (bool, error) {
		if err := checkNodeResource(ctx, endpoint.Host, address); err != nil {
			return false, err
		}
		// Singleton: a success can no longer belong to addresses[1] while the
		// runtime receives addresses[0]. Public validation is done by Check.
		return c.dialTransport(ctx, endpoint, []netip.Addr{address})
	}, c.currentTime)
}
