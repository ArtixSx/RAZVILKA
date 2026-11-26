package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

var ErrXraySelectedTCPRedirect = errors.New("selected Xray TCP redirect scope unavailable or changed")

var xraySelectedTCPServiceID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// XraySelectedTCPPortRange is an explicit closed TCP destination-port range.
// Empty ports never select every port. No UDP/domain transport is implied.
type XraySelectedTCPPortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// XraySelectedTCPRedirectSpec is compiler comparison input, not admission.
// The first vertical has one service/node and one original IPv4 ingress.
// Listener is the actual ingress-reachable address to be independently proven
// by the native listener/PID/config owner before any PREROUTING attachment.
// LAN.Sources describes selected packet senders; it does not identify the
// router's primary ingress address. A one-client /32 must remain a /32 even
// when the listener binds a different address on that original interface.
// LAN is used only for physical match data; its legacy global effects MUST NOT
// be applied by this consumer. CORE binds the distinct runtime mode.
type XraySelectedTCPRedirectSpec struct {
	Schema               int                        `json:"schema"`
	Generation           string                     `json:"generation"`
	ServiceID            string                     `json:"service_id"`
	NodeID               string                     `json:"node_id"`
	LAN                  *LANPolicyRuntimePlan      `json:"lan"`
	Destinations         []string                   `json:"destinations"`
	ExcludedDestinations []string                   `json:"excluded_destinations,omitempty"`
	Ports                []XraySelectedTCPPortRange `json:"ports"`
	Listener             netip.AddrPort             `json:"listener"`
}

func (s XraySelectedTCPRedirectSpec) Clone() XraySelectedTCPRedirectSpec {
	s.LAN = CloneLANPolicyRuntime(s.LAN)
	s.Destinations = slices.Clone(s.Destinations)
	s.ExcludedDestinations = slices.Clone(s.ExcludedDestinations)
	s.Ports = slices.Clone(s.Ports)
	return s
}

func canonicalXraySelectedTCPRedirect(s XraySelectedTCPRedirectSpec) (XraySelectedTCPRedirectSpec, error) {
	if s.Schema != 1 || !validNetworkPolicyGeneration(s.Generation) || !xraySelectedTCPServiceID.MatchString(s.ServiceID) ||
		!exactNodeIDPattern.MatchString(s.NodeID) || ValidateLANPolicyRuntime(s.LAN) != nil || s.LAN.Generation != s.Generation ||
		len(s.LAN.Ingress) != 1 || len(s.Destinations) == 0 || len(s.Destinations) > 1024 || len(s.ExcludedDestinations) > 128 ||
		len(s.Ports) == 0 || len(s.Ports) > 16 || !s.Listener.IsValid() || s.Listener.Port() < 1024 {
		return XraySelectedTCPRedirectSpec{}, ErrXraySelectedTCPRedirect
	}
	address := s.Listener.Addr()
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return XraySelectedTCPRedirectSpec{}, ErrXraySelectedTCPRedirect
	}
	g := s.LAN.Ingress[0]
	for _, list := range [][]string{g.Sources, g.ExcludedSources} {
		for _, value := range list {
			p, err := netip.ParsePrefix(value)
			if err != nil || !p.Addr().Is4() {
				return XraySelectedTCPRedirectSpec{}, ErrXraySelectedTCPRedirect
			}
		}
	}
	for _, list := range [][]string{s.Destinations, s.ExcludedDestinations} {
		seen := map[string]bool{}
		for _, value := range list {
			p, err := netip.ParsePrefix(value)
			if err != nil || !p.Addr().Is4() || p != p.Masked() || !publicfetch.PublicPrefix(p) || seen[value] {
				return XraySelectedTCPRedirectSpec{}, ErrXraySelectedTCPRedirect
			}
			seen[value] = true
		}
	}
	s = s.Clone()
	sort.Strings(s.Destinations)
	sort.Strings(s.ExcludedDestinations)
	sort.Slice(s.Ports, func(i, j int) bool { return s.Ports[i].First < s.Ports[j].First })
	for i, ports := range s.Ports {
		if ports.First == 0 || ports.Last < ports.First || i > 0 && ports.First <= s.Ports[i-1].Last {
			return XraySelectedTCPRedirectSpec{}, ErrXraySelectedTCPRedirect
		}
	}
	return s, nil
}

func xraySelectedTCPPortMatch(p XraySelectedTCPPortRange) string {
	first := strconv.Itoa(int(p.First))
	if p.First == p.Last {
		return first
	}
	return first + ":" + strconv.Itoa(int(p.Last))
}

// CompileXraySelectedTCPRedirect emits only consumer-local IPv4 nat rules.
// Every attachment depends on the ENTIRE completed negative/positive body.
// No process/listener admission, Ready or kernel ownership follows from it.
func CompileXraySelectedTCPRedirect(spec XraySelectedTCPRedirectSpec) (PolicyEffectPlan, error) {
	s, err := canonicalXraySelectedTCPRedirect(spec)
	if err != nil {
		return PolicyEffectPlan{}, err
	}
	g := s.LAN.Ingress[0]
	macs := g.IncludedMACs
	if g.Membership == "all" {
		macs = []string{""}
	}
	bodySize := 2 + len(g.ExcludedSources) + len(g.ExcludedMACs) + len(s.ExcludedDestinations) + len(s.Destinations)*len(s.Ports)
	attachmentSize := len(g.Sources) * len(macs)
	if bodySize+attachmentSize > MaxPolicyEffects || bodySize*attachmentSize > maxPolicyEffectPlanNeeds {
		return PolicyEffectPlan{}, ErrXraySelectedTCPRedirect
	}
	digest := nodeServiceProofDigest(s)
	chain := "RZX_" + digest[:20]
	p := PolicyEffectPlan{Generation: digest}
	p.Effects = append(p.Effects, PolicyEffect{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-N", chain}, Delete: []string{"-t", "nat", "-X", chain}})
	rule := func(args []string) {
		previous := len(p.Effects) - 1
		p.Effects = append(p.Effects, PolicyEffect{Tool: PolicyEffectIPTables,
			Add: append([]string{"-t", "nat", "-A", chain}, args...), Delete: append([]string{"-t", "nat", "-D", chain}, args...), Needs: []int{previous}})
	}
	for _, source := range g.ExcludedSources {
		rule([]string{"-s", source, "-j", "RETURN"})
	}
	for _, mac := range g.ExcludedMACs {
		rule([]string{"-m", "mac", "--mac-source", mac, "-j", "RETURN"})
	}
	for _, destination := range s.ExcludedDestinations {
		rule([]string{"-d", destination, "-j", "RETURN"})
	}
	for _, destination := range s.Destinations {
		for _, ports := range s.Ports {
			rule([]string{"-p", "tcp", "-d", destination, "--dport", xraySelectedTCPPortMatch(ports), "-j", "REDIRECT", "--to-ports", strconv.Itoa(int(s.Listener.Port()))})
		}
	}
	rule([]string{"-j", "RETURN"})
	ready := make([]int, len(p.Effects))
	for i := range ready {
		ready[i] = i
	}
	for _, source := range g.Sources {
		for _, mac := range macs {
			match := []string{"-i", g.Interface, "-s", source, "-p", "tcp"}
			if mac != "" {
				match = append(match, "-m", "mac", "--mac-source", mac)
			}
			match = append(match, "-j", chain)
			p.Effects = append(p.Effects, PolicyEffect{Tool: PolicyEffectIPTables,
				Add: append([]string{"-t", "nat", "-I", "PREROUTING", "1"}, match...), Delete: append([]string{"-t", "nat", "-D", "PREROUTING"}, match...), Needs: slices.Clone(ready)})
		}
	}
	if _, err := PolicyEffectPlanDigest(p); err != nil {
		return PolicyEffectPlan{}, errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	return p, nil
}

// This private material is derived from the actual original proof's open
// Store, never caller config bytes or a borrowed parent-service health DTO.
// It is still preparation only: CORE must publish the original runtime owner
// and prove the actual socket/process before attaching compiled selectors.
type xraySelectedTCPRedirectMaterial struct {
	spec   XraySelectedTCPRedirectSpec
	proof  *NodeServiceProofReview
	ref    NodeServiceProofReference
	config []byte
	host   string
	pin    netip.Addr
}

func (*xraySelectedTCPRedirectMaterial) String() string {
	return "[private selected Xray TCP material]"
}
func (*xraySelectedTCPRedirectMaterial) GoString() string {
	return "[private selected Xray TCP material]"
}

func buildXraySelectedTCPRedirectMaterial(ctx context.Context, original *ProxyTunnelAdapter, proof *NodeServiceProofReview, spec XraySelectedTCPRedirectSpec) (*xraySelectedTCPRedirectMaterial, error) {
	s, err := canonicalXraySelectedTCPRedirect(spec)
	if err != nil || original == nil || original.ID() != "xray" || proof == nil {
		return nil, errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	ref, err := proof.Observation(ctx)
	if err != nil || ref.NodeID != s.NodeID || ref.ServiceID != s.ServiceID || len(proof.service.Domains) != 0 ||
		!slices.Equal(sortedUnique(proof.service.CIDRs), s.Destinations) {
		return nil, errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	material, err := proof.source.store.MaterializeXray(ctx, []nodestore.RouteBinding{{ServiceID: ref.ServiceID, NodeID: ref.NodeID, NetworkProfile: ref.WANProfile, Destinations: slices.Clone(proof.service.CIDRs)}}, proof.now().UTC())
	defer clear(material.Config)
	requests := []NodeRouteRequest{{ServiceID: ref.ServiceID, NodeID: ref.NodeID, Destinations: slices.Clone(proof.service.CIDRs)}}
	if err != nil || material.EngineID != "xray" || nodeDefaultSourceMaterialHash(material.Config) != ref.CompiledMaterialSHA256 || validateScopedXrayConfig(material.Config, requests, 0) != nil {
		return nil, errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	var doc map[string]any
	if json.Unmarshal(material.Config, &doc) != nil {
		return nil, ErrXraySelectedTCPRedirect
	}
	outbound := doc["outbounds"].([]any)[1].(map[string]any)
	server := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	host := server["address"].(string)
	addresses, err := original.resolveNodeEndpoint(ctx, host)
	if err != nil {
		return nil, errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	var pin netip.Addr
	for _, address := range addresses {
		if address.Is4() {
			pin = address
			break
		}
	}
	if !pin.IsValid() {
		return nil, ErrXraySelectedTCPRedirect
	}
	// Preserve implicit domain SNI before replacing only the dial IP. XHTTP's
	// absent Host inherits TLS/REALITY ServerName in v26.3.27, so keep it absent:
	// substituting the dial host would change an explicitly different SNI host.
	stream := outbound["streamSettings"].(map[string]any)
	if _, literal := netip.ParseAddr(host); literal != nil {
		for _, name := range []string{"tlsSettings", "realitySettings"} {
			if settings, ok := stream[name].(map[string]any); ok && settings["serverName"] == "" {
				settings["serverName"] = host
			}
		}
	}
	server["address"] = pin.String()
	const inboundTag = "rz-selected-tcp-in"
	doc["inbounds"] = []any{map[string]any{"tag": inboundTag, "listen": s.Listener.Addr().String(), "port": int(s.Listener.Port()), "protocol": "dokodemo-door",
		"settings": map[string]any{"network": "tcp", "followRedirect": true}, "streamSettings": map[string]any{"network": "tcp", "sockopt": map[string]any{"tproxy": "redirect"}}}}
	var rules []any
	if len(s.ExcludedDestinations) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": s.ExcludedDestinations, "outboundTag": "rz-node-block"})
	}
	for _, ports := range s.Ports {
		port := strings.ReplaceAll(xraySelectedTCPPortMatch(ports), ":", "-")
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{inboundTag}, "network": "tcp", "ip": s.Destinations, "port": port, "outboundTag": scopedNodeTag(ref.NodeID)})
	}
	rules = append(rules, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "rz-node-block"})
	doc["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": rules}
	config, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	r := &xraySelectedTCPRedirectMaterial{spec: s, proof: proof, ref: ref, config: config, host: host, pin: pin}
	if err := r.current(ctx, original); err != nil {
		clear(config)
		return nil, err
	}
	return r, nil
}

func (r *xraySelectedTCPRedirectMaterial) current(ctx context.Context, original *ProxyTunnelAdapter) error {
	if r == nil || original == nil || len(r.config) == 0 || r.proof == nil {
		return ErrXraySelectedTCPRedirect
	}
	ref, err := r.proof.Observation(ctx)
	if err != nil || !reflect.DeepEqual(ref, r.ref) {
		return errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	addresses, err := original.resolveNodeEndpoint(ctx, r.host)
	if err != nil || !slices.Contains(addresses, r.pin) {
		return errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	ref, err = r.proof.Observation(ctx)
	if err != nil || !reflect.DeepEqual(ref, r.ref) {
		return errors.Join(ErrXraySelectedTCPRedirect, err)
	}
	return ctx.Err()
}
