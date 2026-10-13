//go:build linux && (amd64 || arm64)

package physicalscope

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type ipv4LANPacketKernelFence struct{ original *kernelFence }

func (f *ipv4LANPacketKernelFence) check(ctx context.Context, t ipv4LANPacketTopology) (uint64, error) {
	if f == nil || f.original == nil || f.original.reader == nil {
		return 0, at("packet.fence.original", nil)
	}
	return f.original.reader.checkPacket(ctx, t)
}
func (f *ipv4LANPacketKernelFence) close() error { return f.original.close() }

func reviewedIPv4LANPacketSource(provider *netidentity.Provider, control *operationgate.ControlEpochReview, root string) ipv4LANPacketSource {
	return ipv4LANPacketSource{
		ref:     control.Reference(),
		current: provider.WithCurrent,
		control: func(ctx context.Context, retained bool) error {
			if !control.MatchesControlRoot(root) {
				return at("packet.control.root", nil)
			}
			if retained {
				return control.CurrentForCleanup(ctx)
			}
			return control.Current(ctx)
		},
		open: func(ctx context.Context) (ipv4LANPacketFence, error) {
			f, err := openFence(ctx)
			if err != nil {
				return nil, err
			}
			original, ok := f.(*kernelFence)
			if !ok {
				_ = f.close()
				return nil, at("packet.fence.original", nil)
			}
			return &ipv4LANPacketKernelFence{original: original}, nil
		},
		capture: func(ctx context.Context, intent IPv4LANPacketIntent) (ipv4LANPacketCapture, error) {
			var in scopeOptionsInput
			var err error
			in.native, err = provider.ReadReviewedStockInterfaces(ctx)
			if err != nil {
				return ipv4LANPacketCapture{}, err
			}
			in.links, err = dump(ctx, 18, 0)
			if err != nil {
				return ipv4LANPacketCapture{}, err
			}
			in.addresses, err = dump(ctx, 22, 0)
			if err != nil {
				return ipv4LANPacketCapture{}, err
			}
			for _, family := range []byte{2, 10} {
				rows, err := dump(ctx, 26, family)
				if err != nil {
					return ipv4LANPacketCapture{}, err
				}
				in.routes = append(in.routes, rows...)
			}
			t, err := packetTopologyFromFacts(in, intent)
			if err != nil {
				return ipv4LANPacketCapture{}, err
			}
			frames := map[byte][]message{}
			for _, family := range []byte{2, 10} {
				frames[family], err = dump(ctx, 30, family)
				if err != nil {
					return ipv4LANPacketCapture{}, err
				}
			}
			return ipv4LANPacketCapture{topology: t, frames: frames}, nil
		},
	}
}
