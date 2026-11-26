package nodequality

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var ErrEndpoint = errors.New("no confirmed endpoint in the bounded address set")

type SelectedEndpoint struct {
	Address      netip.Addr
	TCPConnectMS *int64
	Checked      bool
}

// SelectEndpoint binds the positive transport result to the same address used
// by the eventual client. The caller must enforce its public-address/SSRF policy
// before this function; this helper does not authorize private destinations.
// UDP protocols have no fake TCP ping; they retain the first address and are
// proved by the actual protocol later. At most sixteen unique addresses tried.
func SelectEndpoint(ctx context.Context, addresses []netip.Addr, tcp bool, dial func(context.Context, netip.Addr) (bool, error), now func() time.Time) (SelectedEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return SelectedEndpoint{}, err
	}
	if len(addresses) == 0 || len(addresses) > 16 || now == nil || tcp && dial == nil {
		return SelectedEndpoint{}, ErrEndpoint
	}
	for _, a := range addresses {
		if !a.IsValid() || a.Zone() != "" {
			return SelectedEndpoint{}, ErrEndpoint
		}
	}
	if !tcp {
		return SelectedEndpoint{Address: addresses[0].Unmap()}, nil
	}
	seen := map[netip.Addr]bool{}
	for _, a := range addresses {
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if err := ctx.Err(); err != nil {
			return SelectedEndpoint{}, err
		}
		start := now()
		checked, err := dial(ctx, a)
		elapsed := now().Sub(start)
		if e := ctx.Err(); e != nil {
			return SelectedEndpoint{}, e
		}
		if err != nil || !checked {
			continue
		}
		r := SelectedEndpoint{Address: a, Checked: true}
		if elapsed >= 0 && elapsed <= 10*time.Minute {
			ms := elapsed.Milliseconds()
			r.TCPConnectMS = &ms
		}
		return r, nil
	}
	return SelectedEndpoint{}, ErrEndpoint
}
