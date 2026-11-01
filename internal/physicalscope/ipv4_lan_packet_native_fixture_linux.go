//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package physicalscope

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// NativeFixtureHomeInterface is classification intent for the isolated Linux
// fixture. Its bridge, addresses, routes, members and FDB are always read from
// the actual kernel. It does not identify a reviewed stock router.
const NativeFixtureHomeInterface = "rzhome"

// ObserveNativeFixtureHome retains the ordinary Linux Observer and its actual
// continuity Review. The tagged caller must create its private namespaces
// before construction; this read-only helper issues no execution admission.
func ObserveNativeFixtureHome(ctx context.Context, provider *netidentity.Provider, selection SelectionReader) (*Observer, *Review, error) {
	if provider == nil || selection == nil {
		return nil, nil, at("fixture.dependencies", nil)
	}
	original := NewLinux(provider, func(c context.Context) (Selection, error) {
		s, err := selection(c)
		if err != nil || s.HomeSegmentID != NativeFixtureHomeInterface || len(s.GuestSegmentIDs) != 0 || len(s.SegmentIDs) != 0 {
			return Selection{}, at("fixture.home", err)
		}
		return s, nil
	})
	review, err := original.Observe(ctx)
	if err != nil {
		return nil, nil, err
	}
	return original, review, nil
}

// NewNativeFixtureIPv4LANPacketScope preserves ProcNetInode and the same real
// control, provider, kernel fence, route and membership readers. Only the Home
// classification comes from the fixed fixture interface instead of NDMC.
func NewNativeFixtureIPv4LANPacketScope(ctx context.Context, provider *netidentity.Provider, control *operationgate.ControlEpochReview, root string, intent IPv4LANPacketIntentReader) (*IPv4LANPacketScope, error) {
	if provider == nil || control == nil || !control.MatchesControlRoot(root) || intent == nil {
		return nil, at("fixture.dependencies", nil)
	}
	source := reviewedIPv4LANPacketSource(provider, control, root)
	source.capture = func(c context.Context, i IPv4LANPacketIntent) (ipv4LANPacketCapture, error) {
		var in scopeOptionsInput
		var err error
		in.links, err = dump(c, 18, 0)
		if err != nil {
			return ipv4LANPacketCapture{}, err
		}
		in.addresses, err = dump(c, 22, 0)
		if err != nil {
			return ipv4LANPacketCapture{}, err
		}
		for _, family := range []byte{2, 10} {
			rows, err := dump(c, 26, family)
			if err != nil {
				return ipv4LANPacketCapture{}, err
			}
			in.routes = append(in.routes, rows...)
		}
		topology, err := packetTopologyFromFactsForSource(in, i, false, NativeFixtureHomeInterface)
		if err != nil {
			return ipv4LANPacketCapture{}, err
		}
		frames := map[byte][]message{}
		for _, family := range []byte{2, 10} {
			frames[family], err = dump(c, 30, family)
			if err != nil {
				return ipv4LANPacketCapture{}, err
			}
		}
		return ipv4LANPacketCapture{topology: topology, frames: frames}, nil
	}
	return newIPv4LANPacketScopeForIdentity(ctx, intent, source, netidentity.ProcNetInode)
}
