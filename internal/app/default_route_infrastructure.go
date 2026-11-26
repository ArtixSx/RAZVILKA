package app

import (
	"net"
	"net/netip"
	"slices"
	"sort"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// DefaultRouteInfrastructureNeighbor preserves an original observed router
// neighbor as a negative fact. It cannot become a positive client or path.
type DefaultRouteInfrastructureNeighbor struct {
	SegmentID, Interface, Address, MAC string
	Flags, Type                        uint8
}

func defaultRouteInfrastructureNegatives(snapshot DefaultRouteSnapshot, segments map[string]autonomy.HomeSegment) (map[string][]string, error) {
	negative := map[string][]string{}
	seen := map[string]bool{}
	for _, neighbor := range snapshot.Infrastructure {
		segment, ok := segments[neighbor.SegmentID]
		mac, macErr := net.ParseMAC(neighbor.MAC)
		ip, ipErr := netip.ParseAddr(neighbor.Address)
		key := neighbor.Interface + "\x00" + neighbor.Address
		if !ok || segment.Interface != neighbor.Interface || !defaultRouteInterface(neighbor.Interface) || macErr != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" || ipErr != nil || ip.Is4In6() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.String() != neighbor.Address || seen[key] {
			return nil, dataplane.ErrReviewChanged
		}
		seen[key] = true
		negative[neighbor.SegmentID] = append(negative[neighbor.SegmentID], mac.String())
	}
	for id, macs := range negative {
		slices.Sort(macs)
		negative[id] = slices.Compact(macs)
	}
	return negative, nil
}

func defaultRouteInfrastructureIdentity(neighbors []DefaultRouteInfrastructureNeighbor) []DefaultRouteInfrastructureNeighbor {
	neighbors = slices.Clone(neighbors)
	for i := range neighbors {
		if mac, err := net.ParseMAC(neighbors[i].MAC); err == nil {
			neighbors[i].MAC = mac.String()
		}
	}
	sort.Slice(neighbors, func(i, j int) bool {
		a, b := neighbors[i], neighbors[j]
		if a.SegmentID != b.SegmentID {
			return a.SegmentID < b.SegmentID
		}
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.MAC != b.MAC {
			return a.MAC < b.MAC
		}
		if a.Flags != b.Flags {
			return a.Flags < b.Flags
		}
		return a.Type < b.Type
	})
	return neighbors
}
