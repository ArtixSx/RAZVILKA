package components

import (
	"fmt"
	"net"
	"net/netip"
)

// usque-keenetic 0.3.0 starts its vendor init from postinst. Its automatic
// address picker pings 172.16.1.100-200 but does not reject local subnet
// overlap. Refuse before opkg can create a persistent conflicting NDM TUN.
func checkUSQUEAutomaticAddresses(addresses []net.Addr) error {
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return fmt.Errorf("USQUE_PACKAGE_NETWORK_UNAVAILABLE: cannot inspect local interface prefix")
		}
		if !prefix.Addr().Is4() {
			continue
		}
		for last := byte(100); last <= 200; last++ {
			if prefix.Contains(netip.AddrFrom4([4]byte{172, 16, 1, last})) {
				return fmt.Errorf("USQUE_PACKAGE_ADDRESS_CONFLICT: vendor startup range 172.16.1.100-172.16.1.200 overlaps local interface %s; review the upstream package network setup before installation", prefix.Masked())
			}
		}
	}
	return nil
}

func (m *Manager) usquePackageNetworkPreflight(id string) error {
	if id != "usque" {
		return nil
	}
	if m.usqueNetworkCheck != nil {
		return m.usqueNetworkCheck()
	}
	// Custom runners are isolated package fixtures, never host admission.
	if _, native := m.Runner.(execRunner); !native {
		return nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("USQUE_PACKAGE_NETWORK_UNAVAILABLE: inspect local interfaces: %w", err)
	}
	return checkUSQUEAutomaticAddresses(addresses)
}
