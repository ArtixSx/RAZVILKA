package nodestore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrRouteProof = errors.New("node route has no current exact service proof")

const (
	// Keep destination-only materialization bounded by the existing service
	// policy and local destination limits. Count raw inputs before deduplication.
	maxRouteBindings         = 128
	maxRouteDestinations     = 512
	maxRouteDestinationBytes = 256
)

// RouteBinding is trusted local intent. NodeID is resolved only inside the
// private store; callers never receive the corresponding credential material.
type RouteBinding struct {
	ServiceID      string
	NodeID         string
	NetworkProfile string
	Domains        []string
	Destinations   []string
}

// RouteMaterial is passed directly to the local dataplane adapter. Config and
// endpoint hosts are private transient data and must never be returned by HTTP.
type RouteMaterial struct {
	EngineID      string
	Config        []byte
	EndpointHosts []string
}

// RouteServices returns the services for which a node has a fresh successful
// exact check on the supplied network. It is safe for selector construction.
func (s *Store) RouteServices(ctx context.Context, nodeID, networkProfile string, now time.Time) ([]string, error) {
	return s.RouteServicesForEngine(ctx, "sing-box", nodeID, networkProfile, now)
}

// RouteServicesForEngine grants eligibility only for the specified executor.
func (s *Store) RouteServicesForEngine(ctx context.Context, engine, nodeID, networkProfile string, now time.Time) ([]string, error) {
	if !validRouteEngine(engine) {
		return nil, ErrRouteProof
	}
	if !validNodeID(nodeID) || !checkTokenPattern.MatchString(networkProfile) || now.IsZero() {
		return nil, ErrStore
	}
	if !systemprobe.ValidWANProfileID(networkProfile) {
		return nil, ErrRouteProof
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	index := nodeIndex(doc, nodeID)
	if index < 0 {
		return nil, ErrNotFound
	}
	return routeServicesForNodeEngine(doc.Nodes[index], engine, networkProfile, now.UTC()), nil
}

// All selector APIs use the same private eligibility calculation. Public
// Health.History is display data and must not grant independent authority.
func routeServicesForNode(node storedNode, networkProfile string, now time.Time) []string {
	return routeServicesForNodeEngine(node, "sing-box", networkProfile, now)
}

func routeServicesForNodeEngine(node storedNode, engine, networkProfile string, now time.Time) []string {
	if node.Disabled || !originFresh(node, now) {
		return []string{}
	}
	// Only the newest exact attempt for a service may grant route authority.
	// DNS, transport and egress failures also revoke an older service PASS.
	latest := map[string]CheckRecord{}
	for _, check := range node.Checks {
		if check.ServiceID != "" && check.NetworkProfile == networkProfile && check.RoutePathID == engine+":"+node.ID {
			latest[check.ServiceID] = check
		}
	}
	services := map[string]bool{}
	for serviceID, check := range latest {
		if routeCheckUsableForEngine(check, engine, node.ID, serviceID, networkProfile, now) {
			services[serviceID] = true
		}
	}
	out := make([]string, 0, len(services))
	for id := range services {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// MaterializeSingBox constructs a deterministic, least-authority config from
// exact registry references. Every binding needs an unexpired service canary
// for this network. A missing, disabled, expired or merely TCP-tested node is
// rejected without exposing which private field failed.
func (s *Store) MaterializeSingBox(ctx context.Context, bindings []RouteBinding, now time.Time) (RouteMaterial, error) {
	return s.materializeEngine(ctx, "sing-box", bindings, now)
}

// MaterializeXray compiles canonical material only with matching Xray proof.
// It supplies no inbound/TUN and blocks every destination outside the bindings.
func (s *Store) MaterializeXray(ctx context.Context, bindings []RouteBinding, now time.Time) (RouteMaterial, error) {
	return s.materializeEngine(ctx, "xray", bindings, now)
}

// ValidateRouteDestinationOwners checks the destination-only routing boundary
// shared by materializers and their local adapters. A SOCKS engine cannot retain
// the original LAN source, so overlapping destinations must use the same node.
// This pure check grants no service, network, or node-health authority.
func ValidateRouteDestinationOwners(bindings []RouteBinding) error {
	if len(bindings) == 0 || len(bindings) > maxRouteBindings {
		return ErrRouteProof
	}
	total := 0
	for _, binding := range bindings {
		if !validNodeID(binding.NodeID) || len(binding.Domains) > maxRouteDestinations-total {
			return ErrRouteProof
		}
		total += len(binding.Domains)
		if len(binding.Destinations) > maxRouteDestinations-total {
			return ErrRouteProof
		}
		total += len(binding.Destinations)
		for _, values := range [][]string{binding.Domains, binding.Destinations} {
			for _, value := range values {
				if len(value) > maxRouteDestinationBytes {
					return ErrRouteProof
				}
			}
		}
	}
	type domainOwner struct{ domain, nodeID string }
	type prefixOwner struct {
		prefix netip.Prefix
		nodeID string
	}
	var domains []domainOwner
	var prefixes []prefixOwner
	for _, binding := range bindings {
		names, err := normalizedDomains(binding.Domains)
		if err != nil {
			return err
		}
		cidrs, err := normalizedDestinations(binding.Destinations)
		if err != nil || len(names)+len(cidrs) == 0 {
			return ErrRouteProof
		}
		for _, name := range names {
			for _, previous := range domains {
				if previous.nodeID != binding.NodeID && (name == previous.domain || strings.HasSuffix(name, "."+previous.domain) || strings.HasSuffix(previous.domain, "."+name)) {
					return ErrRouteProof
				}
			}
			domains = append(domains, domainOwner{name, binding.NodeID})
		}
		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return ErrRouteProof
			}
			for _, previous := range prefixes {
				if previous.nodeID != binding.NodeID && prefix.Overlaps(previous.prefix) {
					return ErrRouteProof
				}
			}
			prefixes = append(prefixes, prefixOwner{prefix, binding.NodeID})
		}
	}
	return nil
}

func (s *Store) materializeEngine(ctx context.Context, engine string, bindings []RouteBinding, now time.Time) (RouteMaterial, error) {
	if now.IsZero() || ValidateRouteDestinationOwners(bindings) != nil {
		return RouteMaterial{}, ErrRouteProof
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return RouteMaterial{}, err
	}
	secrets := make(map[string]json.RawMessage, len(doc.Secrets))
	for _, item := range doc.Secrets {
		secrets[item.Ref] = item.Outbound
	}
	requested := map[string]storedNode{}
	for _, binding := range bindings {
		if !validNodeID(binding.NodeID) || !sourcePattern.MatchString(binding.ServiceID) || !systemprobe.ValidWANProfileID(binding.NetworkProfile) {
			return RouteMaterial{}, ErrRouteProof
		}
		index := nodeIndex(doc, binding.NodeID)
		if index < 0 || doc.Nodes[index].Disabled || !originFresh(doc.Nodes[index], now) || !nodeHasRouteProofForEngine(doc.Nodes[index], engine, binding, now) {
			return RouteMaterial{}, ErrRouteProof
		}
		if engine == "sing-box" {
			var outbound map[string]any
			if json.Unmarshal(secrets[doc.Nodes[index].SecretRef], &outbound) != nil {
				return RouteMaterial{}, ErrStore
			}
			_, contract := providerprofile.SingBoxRuntimeOutbound(outbound)
			check, _ := latestRouteCheckForEngine(doc.Nodes[index], engine, binding.ServiceID, binding.NetworkProfile)
			if contract != "" && check.RuntimeContract != contract {
				return RouteMaterial{}, ErrRouteProof
			}
		}
		requested[binding.NodeID] = doc.Nodes[index]
	}

	nodeIDs := make([]string, 0, len(requested))
	for id := range requested {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	outbounds := make([]any, 0, len(nodeIDs)+2)
	if engine == "xray" {
		// Xray defaults to the first outbound if routing misses. Keep that
		// default fail-closed even before the managed adapter adds its inbound.
		outbounds = append(outbounds, map[string]any{"protocol": "blackhole", "tag": "rz-node-block", "settings": map[string]any{}})
	}
	endpointSet := map[string]bool{}
	for _, id := range nodeIDs {
		node := requested[id]
		var outbound map[string]any
		if json.Unmarshal(secrets[node.SecretRef], &outbound) != nil || len(outbound) == 0 {
			return RouteMaterial{}, ErrStore
		}
		if engine == "sing-box" && !providerprofile.SingBoxSupportsOutbound(outbound) {
			return RouteMaterial{}, ErrRouteProof
		}
		if engine == "sing-box" {
			outbound, _ = providerprofile.SingBoxRuntimeOutbound(outbound)
		}
		collectPrivateEndpointHosts(outbound, endpointSet)
		if engine == "xray" {
			var err error
			outbound, err = compileXrayNodeOutbound(secrets[node.SecretRef])
			if err != nil {
				return RouteMaterial{}, err
			}
		}
		outbound["tag"] = nodeTag(id)
		outbounds = append(outbounds, outbound)
	}
	if engine == "sing-box" {
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "rz-node-direct"}, map[string]any{"type": "block", "tag": "rz-node-block"})
	}

	rules := make([]any, 0, len(bindings)+1)
	for _, binding := range bindings {
		domains, err := normalizedDomains(binding.Domains)
		if err != nil {
			return RouteMaterial{}, ErrRouteProof
		}
		cidrs, err := normalizedDestinations(binding.Destinations)
		if err != nil || len(domains)+len(cidrs) == 0 {
			return RouteMaterial{}, ErrRouteProof
		}
		if engine == "xray" {
			if len(domains) > 0 {
				matches := make([]string, len(domains))
				for i, domain := range domains {
					matches[i] = "domain:" + domain
				}
				rules = append(rules, map[string]any{"type": "field", "domain": matches, "outboundTag": nodeTag(binding.NodeID)})
			}
			if len(cidrs) > 0 {
				rules = append(rules, map[string]any{"type": "field", "ip": cidrs, "outboundTag": nodeTag(binding.NodeID)})
			}
			continue
		}
		rule := map[string]any{"outbound": nodeTag(binding.NodeID)}
		if len(domains) > 0 {
			rule["domain_suffix"] = domains
		}
		if len(cidrs) > 0 {
			rule["ip_cidr"] = cidrs
		}
		rules = append(rules, rule)
	}
	document := map[string]any{
		"outbounds": outbounds,
		"route":     map[string]any{"rules": rules, "final": "rz-node-block", "auto_detect_interface": true},
	}
	if engine == "xray" {
		rules = append(rules, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "rz-node-block"})
		document = map[string]any{
			"log":       map[string]any{"loglevel": "warning", "access": "none"},
			"outbounds": outbounds,
			"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
		}
	}
	config, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return RouteMaterial{}, ErrStore
	}
	endpoints := make([]string, 0, len(endpointSet))
	for host := range endpointSet {
		endpoints = append(endpoints, host)
	}
	sort.Strings(endpoints)
	return RouteMaterial{EngineID: engine, Config: config, EndpointHosts: endpoints}, nil
}

func compileXrayNodeOutbound(raw []byte) (map[string]any, error) {
	profile, err := providerprofile.VLESSProfileFromJSON(raw)
	if err != nil {
		return nil, ErrRouteProof
	}
	config, _, err := providerprofile.CompileXrayConfig(profile)
	if err != nil {
		return nil, ErrRouteProof
	}
	defer clear(config)
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(config, &document) != nil || len(document.Outbounds) != 1 {
		return nil, ErrStore
	}
	return document.Outbounds[0], nil
}

func nodeIndex(doc document, id string) int {
	for index := range doc.Nodes {
		if doc.Nodes[index].ID == id {
			return index
		}
	}
	return -1
}

func originFresh(node storedNode, now time.Time) bool {
	for _, origin := range node.Origins {
		if !now.Before(origin.ReceivedAt) && now.Before(origin.ExpiresAt) {
			return true
		}
	}
	return false
}

func nodeHasRouteProof(node storedNode, binding RouteBinding, now time.Time) bool {
	return nodeHasRouteProofForEngine(node, "sing-box", binding, now)
}

func nodeHasRouteProofForEngine(node storedNode, engine string, binding RouteBinding, now time.Time) bool {
	check, ok := latestRouteCheckForEngine(node, engine, binding.ServiceID, binding.NetworkProfile)
	if !ok {
		return false
	}
	return routeCheckUsableForEngine(check, engine, node.ID, binding.ServiceID, binding.NetworkProfile, now)
}

func latestRouteCheck(node storedNode, serviceID, profile string) (CheckRecord, bool) {
	return latestRouteCheckForEngine(node, "sing-box", serviceID, profile)
}

func latestRouteCheckForEngine(node storedNode, engine, serviceID, profile string) (CheckRecord, bool) {
	for index := len(node.Checks) - 1; index >= 0; index-- {
		check := node.Checks[index]
		if check.ServiceID == serviceID && check.NetworkProfile == profile && check.RoutePathID == engine+":"+node.ID {
			return check, true
		}
	}
	return CheckRecord{}, false
}

func routeCheckUsable(check CheckRecord, nodeID, serviceID, profile string, now time.Time) bool {
	return routeCheckUsableForEngine(check, "sing-box", nodeID, serviceID, profile, now)
}

func routeCheckUsableForEngine(check CheckRecord, engine, nodeID, serviceID, profile string, now time.Time) bool {
	return validRouteEngine(engine) && systemprobe.ValidWANProfileID(profile) && check.ServiceID == serviceID && check.NetworkProfile == profile && check.RoutePathID == engine+":"+nodeID &&
		check.TestLevel == "service" && check.Verdict == "PASS" && check.State == "available" && !check.DirectLeak && !now.Before(check.CheckedAt) && now.Before(check.ExpiresAt)
}

func validRouteEngine(engine string) bool { return engine == "sing-box" || engine == "xray" }

func validExactRoute(route, nodeID string) bool {
	return validNodeID(nodeID) && (route == "sing-box:"+nodeID || route == "xray:"+nodeID)
}

func nodeTag(id string) string { return "rz-node-" + id[len("node-"):len("node-")+16] }

func normalizedDomains(values []string) ([]string, error) {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		value = strings.TrimPrefix(value, "*.")
		if len(value) == 0 || len(value) > 253 {
			return nil, ErrRouteProof
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, ErrRouteProof
			}
			for _, ch := range label {
				if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
					return nil, ErrRouteProof
				}
			}
		}
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func normalizedDestinations(values []string) ([]string, error) {
	seen := map[string]bool{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil || address.Is4In6() {
				return nil, ErrRouteProof
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4In6() {
			return nil, ErrRouteProof
		}
		address := prefix.Addr().Unmap()
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
			return nil, ErrRouteProof
		}
		canonical := netip.PrefixFrom(address, prefix.Bits()).Masked()
		if !canonical.IsValid() {
			return nil, ErrRouteProof
		}
		seen[canonical.String()] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func collectPrivateEndpointHosts(outbound map[string]any, seen map[string]bool) {
	// This is a validated canonical node, whose only remote endpoint is its
	// top-level server. Transport headers/extra and TLS names are private
	// protocol data, never DNS or route-exclusion authority.
	server, _ := outbound["server"].(string)
	host := strings.Trim(strings.TrimSpace(server), "[]")
	if split, _, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(split, "[]")
	}
	if host != "" && host != "127.0.0.1" && host != "::1" {
		seen[host] = true
	}
}
