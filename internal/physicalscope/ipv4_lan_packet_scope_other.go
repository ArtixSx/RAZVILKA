//go:build !linux || (!amd64 && !arm64)

package physicalscope

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func reviewedIPv4LANPacketSource(*netidentity.Provider, *operationgate.ControlEpochReview, string) ipv4LANPacketSource {
	return ipv4LANPacketSource{
		current: func(context.Context, func(context.Context, netidentity.Identity) error) error {
			return at("packet.platform.unavailable", nil)
		},
		control: func(context.Context, bool) error { return at("packet.platform.unavailable", nil) },
		open:    func(context.Context) (ipv4LANPacketFence, error) { return nil, at("packet.platform.unavailable", nil) },
		capture: func(context.Context, IPv4LANPacketIntent) (ipv4LANPacketCapture, error) {
			return ipv4LANPacketCapture{}, at("packet.platform.unavailable", nil)
		},
	}
}
