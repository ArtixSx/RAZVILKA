package dataplane

import "net/netip"

// A separate closed predicate for the private domain backend. It does not
// broaden selected-TCP's LAN listener predicate or create a resource/Ready
// owner. The actual original child FD and process/config/provider bookends
// must surround this complete-table comparison in the native reader.
func xrayDomainTCPListenerInode(v4, v6 []xraySelectedTCPSocketRow, endpoint netip.AddrPort) (uint64, error) {
	if !endpoint.IsValid() || endpoint.Addr() != netip.MustParseAddr("127.0.0.1") || endpoint.Port() < 1024 || endpoint.Port() == 8787 {
		return 0, ErrXrayDomainTCPOriginal
	}
	var inode uint64
	for _, row := range v4 {
		if row.state != 10 || row.local.Port() != endpoint.Port() {
			continue
		}
		if row.local.Addr().IsUnspecified() || row.local == endpoint {
			if row.local != endpoint || row.inode == 0 || inode != 0 {
				return 0, ErrXrayDomainTCPOriginal
			}
			inode = row.inode
		}
	}
	for _, row := range v6 {
		if row.state == 10 && row.local.Port() == endpoint.Port() && (row.local.Addr().IsUnspecified() || row.local.Addr().Unmap() == endpoint.Addr()) {
			return 0, ErrXrayDomainTCPOriginal // No v6only/reuseport inference.
		}
	}
	if inode == 0 {
		return 0, ErrXrayDomainTCPOriginal
	}
	return inode, nil
}
