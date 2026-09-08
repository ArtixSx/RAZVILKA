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

	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrRouteProof = errors.New("node route has no current exact service proof")

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
	Config        []byte
	EndpointHosts []string
}

// RouteServices returns the services for which a node has a fresh successful
// exact check on the supplied network. It is safe for selector construction.
func (s *Store) RouteServices(ctx context.Context, nodeID, networkProfile string, now time.Time) ([]string, error) {
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
	if doc.Nodes[index].Disabled || !originFresh(doc.Nodes[index], now.UTC()) {
		return []string{}, nil
	}
	// Only the newest exact attempt for a service may grant route authority.
	// DNS, transport and egress failures also revoke an older service PASS.
	latest := map[string]CheckRecord{}
	for _, check := range doc.Nodes[index].Checks {
		if check.ServiceID != "" && check.NetworkProfile == networkProfile && check.RoutePathID == "sing-box:"+nodeID {
			latest[check.ServiceID] = check
		}
	}
	services := map[string]bool{}
	for serviceID, check := range latest {
		if routeCheckUsable(check, nodeID, serviceID, networkProfile, now.UTC()) {
			services[serviceID] = true
		}
	}
	out := make([]string, 0, len(services))
	for id := range services {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// MaterializeSingBox constructs a deterministic, least-authority config from
// exact registry references. Every binding needs an unexpired service canary
// for this network. A missing, disabled, expired or merely TCP-tested node is
// rejected without exposing which private field failed.
func (s *Store) MaterializeSingBox(ctx context.Context, bindings []RouteBinding, now time.Time) (RouteMaterial, error) {
	if len(bindings) == 0 || now.IsZero() {
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
		if index < 0 || doc.Nodes[index].Disabled || !originFresh(doc.Nodes[index], now) || !nodeHasRouteProof(doc.Nodes[index], binding, now) {
			return RouteMaterial{}, ErrRouteProof
		}
		requested[binding.NodeID] = doc.Nodes[index]
	}

	nodeIDs := make([]string, 0, len(requested))
	for id := range requested {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	outbounds := make([]any, 0, len(nodeIDs)+2)
	endpointSet := map[string]bool{}
	for _, id := range nodeIDs {
		node := requested[id]
		var outbound map[string]any
		if json.Unmarshal(secrets[node.SecretRef], &outbound) != nil || len(outbound) == 0 {
			return RouteMaterial{}, ErrStore
		}
		outbound["tag"] = nodeTag(id)
		outbounds = append(outbounds, outbound)
		collectPrivateEndpointHosts(outbound, endpointSet)
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "rz-node-direct"}, map[string]any{"type": "block", "tag": "rz-node-block"})

	rules := make([]any, 0, len(bindings)+1)
	seenDestination := map[string]string{}
	for _, binding := range bindings {
		domains := normalizedDomains(binding.Domains)
		cidrs, err := normalizedDestinations(binding.Destinations)
		if err != nil || len(domains)+len(cidrs) == 0 {
			return RouteMaterial{}, ErrRouteProof
		}
		for _, destination := range append(append([]string{}, domains...), cidrs...) {
			if owner, exists := seenDestination[destination]; exists && owner != binding.NodeID {
				return RouteMaterial{}, ErrRouteProof
			}
			seenDestination[destination] = binding.NodeID
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
	config, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return RouteMaterial{}, ErrStore
	}
	endpoints := make([]string, 0, len(endpointSet))
	for host := range endpointSet {
		endpoints = append(endpoints, host)
	}
	sort.Strings(endpoints)
	return RouteMaterial{Config: config, EndpointHosts: endpoints}, nil
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
	check, ok := latestRouteCheck(node, binding.ServiceID, binding.NetworkProfile)
	if !ok {
		return false
	}
	return routeCheckUsable(check, node.ID, binding.ServiceID, binding.NetworkProfile, now)
}

func latestRouteCheck(node storedNode, serviceID, profile string) (CheckRecord, bool) {
	for index := len(node.Checks) - 1; index >= 0; index-- {
		check := node.Checks[index]
		if check.ServiceID == serviceID && check.NetworkProfile == profile && check.RoutePathID == "sing-box:"+node.ID {
			return check, true
		}
	}
	return CheckRecord{}, false
}

func routeCheckUsable(check CheckRecord, nodeID, serviceID, profile string, now time.Time) bool {
	return systemprobe.ValidWANProfileID(profile) && check.ServiceID == serviceID && check.NetworkProfile == profile && check.RoutePathID == "sing-box:"+nodeID &&
		check.TestLevel == "service" && check.Verdict == "PASS" && check.State == "available" && !check.DirectLeak && !now.Before(check.CheckedAt) && now.Before(check.ExpiresAt)
}

func nodeTag(id string) string { return "rz-node-" + id[len("node-"):len("node-")+16] }

func normalizedDomains(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		value = strings.TrimPrefix(value, "*.")
		if value != "" && !strings.ContainsAny(value, " /\\\x00") {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizedDestinations(values []string) ([]string, error) {
	seen := map[string]bool{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, ErrRouteProof
			}
			prefix = netip.PrefixFrom(address.Unmap(), address.BitLen())
		}
		address := prefix.Addr().Unmap()
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
			return nil, ErrRouteProof
		}
		seen[netip.PrefixFrom(address, prefix.Bits()).Masked().String()] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func collectPrivateEndpointHosts(value any, seen map[string]bool) {
	var walk func(any, string)
	walk = func(current any, key string) {
		switch item := current.(type) {
		case map[string]any:
			for childKey, child := range item {
				walk(child, strings.ToLower(childKey))
			}
		case []any:
			for _, child := range item {
				walk(child, key)
			}
		case string:
			if key != "server" && key != "address" && key != "endpoint" {
				return
			}
			host := strings.Trim(strings.TrimSpace(item), "[]")
			if split, _, err := net.SplitHostPort(host); err == nil {
				host = strings.Trim(split, "[]")
			}
			if host != "" && host != "127.0.0.1" && host != "::1" {
				seen[host] = true
			}
		}
	}
	walk(value, "")
}
