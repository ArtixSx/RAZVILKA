package dataplane

import "net/netip"

func xraySelectedTCPListenerAbsent(v4, v6 []xraySelectedTCPSocketRow, endpoint netip.AddrPort) error {
	if !endpoint.IsValid() || !endpoint.Addr().Is4() || !endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().IsLoopback() || endpoint.Addr().IsLinkLocalUnicast() || endpoint.Port() < 1024 {
		return errXraySelectedTCPRuntime
	}
	for _, rows := range [][]xraySelectedTCPSocketRow{v4, v6} {
		for _, row := range rows {
			if row.state == 10 && row.local.Port() == endpoint.Port() && (row.local.Addr().IsUnspecified() || row.local.Addr().Unmap() == endpoint.Addr()) {
				return errXraySelectedTCPRuntime
			}
		}
	}
	return nil
}
