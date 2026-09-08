package cloudflareprovider

import "net/netip"

const (
	EndpointOfficialConsumer  = "official-consumer-wireguard"
	EndpointOfficialZeroTrust = "official-zero-trust-wireguard"
	EndpointRegistrarIssued   = "registrar-issued-unverified"
	PortOfficialDefault       = "official-default"
	PortOfficialFallback      = "official-fallback"
	PortRegistrarIssued       = "registrar-issued-unverified"
	EndpointCatalogVersion    = "cloudflare-firewall-2026-07-24"
	EndpointCatalogSource     = "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/"
)

var (
	consumerWARPv4    = netip.MustParsePrefix("162.159.192.0/24")
	zeroTrustWARPv4   = netip.MustParsePrefix("162.159.193.0/24")
	zeroTrustWARPv6   = netip.MustParsePrefix("2606:4700:100::/48")
	officialWARPPorts = []uint16{2408, 500, 1701, 4500}
)

type EndpointAssessment struct {
	Endpoint       string `json:"endpoint"`
	AddressClass   string `json:"address_class"`
	PortClass      string `json:"port_class"`
	CatalogVersion string `json:"catalog_version"`
	Source         string `json:"source"`
	Recommended    bool   `json:"recommended"`
}

// ClassifyEndpoint never discovers or adds endpoints. It only annotates an
// endpoint already issued by the registrar, keeping undocumented values
// available for isolated testing without calling them official.
func ClassifyEndpoint(endpoint netip.AddrPort) EndpointAssessment {
	assessment := EndpointAssessment{
		Endpoint: endpoint.String(), AddressClass: EndpointRegistrarIssued,
		PortClass: PortRegistrarIssued, CatalogVersion: EndpointCatalogVersion, Source: EndpointCatalogSource,
	}
	address := endpoint.Addr().Unmap()
	switch {
	case consumerWARPv4.Contains(address):
		assessment.AddressClass = EndpointOfficialConsumer
	case zeroTrustWARPv4.Contains(address), zeroTrustWARPv6.Contains(address):
		assessment.AddressClass = EndpointOfficialZeroTrust
	}
	switch endpoint.Port() {
	case 2408:
		assessment.PortClass = PortOfficialDefault
	case 500, 1701, 4500:
		assessment.PortClass = PortOfficialFallback
	}
	assessment.Recommended = assessment.AddressClass != EndpointRegistrarIssued && assessment.PortClass != PortRegistrarIssued
	return assessment
}

func OfficialWARPPorts() []uint16 {
	return append([]uint16(nil), officialWARPPorts...)
}
