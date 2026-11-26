package dataplane

import (
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// LookupNetIP can represent an ordinary IPv4 answer as a 16-byte mapped
// address. Normalize that representation, preserving every answer for the
// original resource guard; true IPv6, zones and non-public IPv4 still refuse.
func mihomoLiveResolvedIPv4(input []netip.Addr) ([]netip.Addr, error) {
	if len(input) == 0 || len(input) > 64 {
		return nil, errMihomoLiveMaterial
	}
	result := make([]netip.Addr, len(input))
	for i, address := range input {
		if address.Zone() != "" {
			return nil, errMihomoLiveMaterial
		}
		address = address.Unmap()
		if !address.Is4() || !publicfetch.PublicAddress(address) {
			return nil, errMihomoLiveMaterial
		}
		result[i] = address
	}
	return result, nil
}
