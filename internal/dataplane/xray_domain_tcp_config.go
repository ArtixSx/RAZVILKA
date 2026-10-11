package dataplane

import (
	"encoding/json"
	"net/netip"
)

// Private compiler only. The bytes must come from the original NodeStore
// materializer under matching service/WAN admission; bytes or a numeric target
// passed directly to this function cannot construct a resource owner.
func compileXrayDomainTCPConfig(material []byte, spec DomainPolicyTCPXraySpec, endpoint, nodePin netip.AddrPort) ([]byte, error) {
	if !spec.valid() || !endpoint.IsValid() || endpoint.Addr() != netip.MustParseAddr("127.0.0.1") || endpoint.Port() < 1024 || endpoint.Port() == 8787 || !nodePin.Addr().Is4() || !domainPolicyTCPPublicIPv4(nodePin.Addr()) {
		return nil, ErrXrayDomainTCPOriginal
	}
	requests := []NodeRouteRequest{{ServiceID: spec.ServiceID, NodeID: spec.NodeID, Domains: []string{spec.Name}}}
	if validateScopedXrayConfig(material, requests, 0) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	var doc map[string]any
	if json.Unmarshal(material, &doc) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	exit := doc["outbounds"].([]any)[1].(map[string]any)
	server := exit["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	host := server["address"].(string)
	port, ok := server["port"].(float64)
	if !ok || port != float64(nodePin.Port()) {
		return nil, ErrXrayDomainTCPOriginal
	}
	if stream, ok := exit["streamSettings"].(map[string]any); ok {
		if _, literal := netip.ParseAddr(host); literal != nil {
			for _, name := range []string{"tlsSettings", "realitySettings"} {
				if settings, ok := stream[name].(map[string]any); ok && (settings["serverName"] == nil || settings["serverName"] == "") {
					settings["serverName"] = host
				}
			}
		}
	}
	server["address"] = nodePin.Addr().String()
	const inbound = "rz-domain-tcp-in"
	doc["inbounds"] = []any{map[string]any{"tag": inbound, "listen": endpoint.Addr().String(), "port": int(endpoint.Port()), "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}
	doc["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": []any{
		map[string]any{"type": "field", "inboundTag": []string{inbound}, "network": "tcp", "ip": []string{netip.PrefixFrom(spec.RealIP, 32).String()}, "port": "80,443", "outboundTag": scopedNodeTag(spec.NodeID)},
		map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "rz-node-block"},
	}}
	// Names belong to the pre-outbound flow/mapping owner. This private engine
	// never performs service-name resolution, sniffing or alternate routing.
	delete(doc, "dns")
	delete(doc, "sniffing")
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		clear(data)
		return nil, ErrXrayDomainTCPOriginal
	}
	return data, nil
}
