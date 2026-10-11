//go:build linux

package dataplane

import (
	"context"
	"net/netip"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Complete parent-namespace tables, inside the SAME actual provider interval.
// No path or reader parameter can supply a negative socket observation.
func xraySelectedTCPObserveListenerAbsent(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, endpoint netip.AddrPort) error {
	if xraySelectedTCPFinite(ctx) != nil || provider == nil || expected.Validate() != nil {
		return errXraySelectedTCPRuntime
	}
	return provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != expected {
			return errXraySelectedTCPRuntime
		}
		proc, err := openXraySelectedTCPProc(held, os.Getpid())
		if err != nil {
			return err
		}
		defer proc.close()
		read := func() error {
			if proc.network(held, expected) != nil {
				return errXraySelectedTCPRuntime
			}
			v4, err := proc.read(held, proc.child, "net/tcp", 8<<20)
			if err != nil {
				return err
			}
			v6, err := proc.read(held, proc.child, "net/tcp6", 8<<20)
			if err != nil {
				return err
			}
			rows4, err := xraySelectedTCPSockets(v4, false)
			if err != nil {
				return err
			}
			rows6, err := xraySelectedTCPSockets(v6, true)
			if err != nil {
				return err
			}
			if xraySelectedTCPListenerAbsent(rows4, rows6, endpoint) != nil || proc.network(held, expected) != nil || proc.current(held) != nil {
				return errXraySelectedTCPRuntime
			}
			return nil
		}
		if err := read(); err != nil {
			return err
		}
		return read()
	})
}
