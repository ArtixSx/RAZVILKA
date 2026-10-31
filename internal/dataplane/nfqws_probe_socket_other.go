//go:build !linux

package dataplane

import (
	"context"
	"net/netip"
	"syscall"
)

type nfqwsProbeBoundSocket struct{}

func nfqwsProbeRouteSource(context.Context, netip.AddrPort) (netip.Addr, error) {
	return netip.Addr{}, errNFQWSProbeSocket
}
func prepareNFQWSProbeBoundSocket(context.Context, syscall.RawConn, netip.Addr, netip.AddrPort) (*nfqwsProbeBoundSocket, error) {
	return nil, errNFQWSProbeSocket
}
func (*nfqwsProbeBoundSocket) current(context.Context) error { return errNFQWSProbeSocket }
func (*nfqwsProbeBoundSocket) close() error                  { return errNFQWSProbeSocket }
