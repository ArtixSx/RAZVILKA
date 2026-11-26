package cloudflareprovider

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestEndpointCatalogKeepsOfficialScopesDistinct(t *testing.T) {
	tests := []struct {
		endpoint     string
		addressClass string
		portClass    string
		recommended  bool
	}{
		{"162.159.192.1:2408", EndpointOfficialConsumer, PortOfficialDefault, true},
		{"162.159.193.10:500", EndpointOfficialZeroTrust, PortOfficialFallback, true},
		{"[2606:4700:100::1]:4500", EndpointOfficialZeroTrust, PortOfficialFallback, true},
		{"[2606:4700:d0::1]:2408", EndpointRegistrarIssued, PortOfficialDefault, false},
		{"8.8.8.8:2408", EndpointRegistrarIssued, PortOfficialDefault, false},
		{"162.159.192.1:51820", EndpointOfficialConsumer, PortRegistrarIssued, false},
	}
	for _, test := range tests {
		assessment := ClassifyEndpoint(netip.MustParseAddrPort(test.endpoint))
		if assessment.Endpoint != test.endpoint || assessment.AddressClass != test.addressClass || assessment.PortClass != test.portClass || assessment.Recommended != test.recommended || assessment.CatalogVersion != EndpointCatalogVersion || assessment.Source != EndpointCatalogSource {
			t.Fatalf("endpoint=%s assessment=%+v", test.endpoint, assessment)
		}
	}
}

func TestOfficialWARPPortsReturnsDetachedOrder(t *testing.T) {
	ports := OfficialWARPPorts()
	if !reflect.DeepEqual(ports, []uint16{2408, 500, 1701, 4500}) {
		t.Fatal(ports)
	}
	ports[0] = 1
	if OfficialWARPPorts()[0] != 2408 {
		t.Fatal("caller mutated endpoint catalog")
	}
}
