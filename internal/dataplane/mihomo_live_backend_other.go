//go:build !linux

package dataplane

import (
	"context"
	"net/netip"
)

func (*mihomoLiveResource) backendDisjoint(context.Context, netip.Addr, netip.Addr) error {
	return errMihomoLiveMaterial
}
