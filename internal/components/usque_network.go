package components

import (
	"fmt"
	"net"
	"net/netip"
)

// usque-keenetic 0.3.0 starts its vendor init from postinst. Its automatic
// address picker pings 172.16.1.100-200 but does not reject local subnet
// overlap. Refuse before opkg can create a persistent conflicting NDM TUN.
// This intentionally includes /32 addresses of a running vendor USQUE: the
// address alone cannot prove that interface ownership permits an exemption.
func checkUSQUEAutomaticAddresses(addresses []net.Addr) error {
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return fmt.Errorf("USQUE_PACKAGE_NETWORK_UNAVAILABLE: не удалось проверить адреса локальных интерфейсов")
		}
		if !prefix.Addr().Is4() {
			continue
		}
		for last := byte(100); last <= 200; last++ {
			if prefix.Contains(netip.AddrFrom4([4]byte{172, 16, 1, last})) {
				return fmt.Errorf("USQUE_PACKAGE_ADDRESS_CONFLICT: автоадреса пакета USQUE 172.16.1.100–172.16.1.200 пересекаются с локальной сетью или адресом %s. Установка и обновление остановлены до проверки настроек пакета. Адрес уже работающего штатного USQUE также вызывает этот запрет: автоматически отличить его от чужого интерфейса нельзя", prefix.Masked())
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
		return fmt.Errorf("USQUE_PACKAGE_NETWORK_UNAVAILABLE: не удалось проверить локальные интерфейсы: %w", err)
	}
	return checkUSQUEAutomaticAddresses(addresses)
}
