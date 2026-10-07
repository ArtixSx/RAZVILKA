package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var (
	ErrNodeTUNProofRequired = errors.New("selected/control TUN client proof is required")
	ErrNodeEndpointChanged  = errors.New("scoped node endpoint or service addresses changed; fresh transaction required")
	ErrNodeDestinationScope = errors.New("one managed SOCKS engine cannot preserve different node owners for overlapping destination scopes")
)

// NewScopedXrayTunnelAdapter is a separate trusted NodeStore integration.
// Generic Xray drafts keep their original single-exit restrictions. Configure
// NodeTUNProbe before use; without an independent LAN client verifier Validate
// refuses, and Health/Commit cannot accept SOCKS evidence as TUN evidence.
func NewScopedXrayTunnelAdapter(configs *engineconfig.Manager, root string, materializer NodeRouteMaterializer) (*ProxyTunnelAdapter, error) {
	if materializer == nil {
		return nil, errors.New("scoped Xray materializer is required")
	}
	a, err := NewProxyTunnelAdapter("xray", configs, root)
	if err != nil {
		return nil, err
	}
	a.scopedXray, a.NodeRoutes = true, materializer
	return a, nil
}

// NewScopedXrayRouterTunnelAdapter selects the concrete router-origin HTTPS
// verifier. Every health attempt still requires Manager's registered transient
// resource and fresh runtime/source readback; construction grants no mutation.
func NewScopedXrayRouterTunnelAdapter(configs *engineconfig.Manager, root string, materializer NodeRouteMaterializer) (*ProxyTunnelAdapter, error) {
	a, err := NewScopedXrayTunnelAdapter(configs, root, materializer)
	if err != nil {
		return nil, err
	}
	a.nodeRouterVerifier = true
	return a, nil
}

// NewXrayRuntimeAdapter installs one owner for reviewed generic or exact-node
// plans. Each operation selects a detached mode before observing or changing
// runtime state; a failed node operation cannot switch to the generic path.
func NewXrayRuntimeAdapter(configs *engineconfig.Manager, root string, materializer NodeRouteMaterializer) (*ProxyTunnelAdapter, error) {
	a, err := NewScopedXrayRouterTunnelAdapter(configs, root, materializer)
	if err != nil {
		return nil, err
	}
	a.scopedXray, a.xrayPlanDispatch = false, true
	return a, nil
}

// NodeRouteVerificationCapable reports an installed concrete verification path.
// Router service evidence remains distinct from optional actual LAN evidence.
func (a *ProxyTunnelAdapter) NodeRouteVerificationCapable() bool {
	return a != nil && (a.scopedXray || a.xrayPlanDispatch) && a.NodeRoutes != nil && a.FreshProfile != nil &&
		(a.NodeTUNProbe != nil || a.nodeRouterVerifier && nodeRouterDeviceBindingAvailable())
}

type proxyNodeEndpoint struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Tag  string `json:"tag"`
}

// Private runtime binding, never a public plan or synthesized launch receipt.
type proxyNodeManifest struct {
	Schema         int                 `json:"schema"`
	Engine         string              `json:"engine"`
	NetworkProfile string              `json:"network_profile"`
	Routes         []Route             `json:"routes"`
	Requests       []NodeRouteRequest  `json:"requests"`
	Endpoints      []proxyNodeEndpoint `json:"endpoints"`
	ConfigHash     string              `json:"config_sha256"`
	SidecarHash    string              `json:"sidecar_sha256"`
}

func (a *ProxyTunnelAdapter) nodeManifestPath() string {
	return filepath.Join(a.runtimeRoot(), "nodes.json")
}

func (a *ProxyTunnelAdapter) scopedRoutes(plan Plan) ([]Route, error) {
	var routes []Route
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() {
			continue
		}
		if !strings.HasPrefix(route.Resolved, "xray:") || !exactNodeIDPattern.MatchString(strings.TrimPrefix(route.Resolved, "xray:")) || len(route.Sources) == 0 || route.ProbeURL == "" {
			return nil, errors.New("scoped Xray requires resolved exact nodes, client sources and service probes")
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 || len(routes) > 64 {
		return nil, errors.New("invalid scoped Xray route count")
	}
	return routes, nil
}

func (a *ProxyTunnelAdapter) nodeRequests(ctx context.Context, routes []Route) ([]NodeRouteRequest, error) {
	var requests []NodeRouteRequest
	for _, route := range routes {
		serviceID, err := a.nodeRequestServiceID(route)
		if err != nil {
			return nil, err
		}
		destinations, err := resolvePolicyPrefixes(ctx, Plan{Routes: []Route{route}}, "xray", a.Resolver)
		if err != nil {
			return nil, err
		}
		requests = append(requests, NodeRouteRequest{ServiceID: serviceID, NodeID: strings.TrimPrefix(route.Resolved, "xray:"), Domains: append([]string{}, route.Domains...), Destinations: destinations})
	}
	return requests, nil
}

func (a *ProxyTunnelAdapter) stageScopedXray(ctx context.Context, plan Plan) ([]byte, []string, *proxyNodeManifest, error) {
	if ctx == nil {
		return nil, nil, nil, ErrExactNodeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	if a.NodeRoutes == nil || a.NodeTUNProbe == nil && !a.nodeRouterVerifier {
		return nil, nil, nil, ErrNodeTUNProofRequired
	}
	routes, err := a.scopedRoutes(plan)
	if err != nil {
		return nil, nil, nil, err
	}
	intent, err := a.nodeIntentRequests(routes)
	if err != nil {
		return nil, nil, nil, err
	}
	preview, err := a.NodeRoutes(ctx, cloneScopedNodeRequests(intent), plan.NetworkProfileID, nowUTC())
	if err != nil || preview.EngineID != "xray" {
		return nil, nil, nil, errors.Join(errors.New("Xray material has no matching executor proof"), err)
	}
	if err := errors.Join(checkAddressRefreshAuthority(ctx), ctx.Err()); err != nil {
		return nil, nil, nil, err
	}
	preview, err = copyScopedNodeMaterial(preview)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(preview.Config)
	if err := validateScopedXrayConfig(preview.Config, intent, 0); err != nil {
		return nil, nil, nil, err
	}
	seal, err := scopedNodeMaterialSeal(preview)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := a.requireScopedXHTTPRuntime(ctx, preview.Config); err != nil {
		return nil, nil, nil, err
	}
	requests, err := a.nodeRequests(ctx, routes)
	if err != nil {
		return nil, nil, nil, err
	}
	material, err := a.NodeRoutes(ctx, cloneScopedNodeRequests(requests), plan.NetworkProfileID, nowUTC())
	if err != nil || material.EngineID != "xray" {
		return nil, nil, nil, errors.Join(errors.New("Xray material has no matching executor proof"), err)
	}
	if err := errors.Join(checkAddressRefreshAuthority(ctx), ctx.Err()); err != nil {
		return nil, nil, nil, err
	}
	material, err = copyScopedNodeMaterial(material)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(material.Config)
	if err := validateScopedXrayConfig(material.Config, requests, 0); err != nil {
		return nil, nil, nil, err
	}
	currentSeal, err := scopedNodeMaterialSeal(material)
	if err != nil || currentSeal != seal {
		return nil, nil, nil, errors.Join(ErrNodeEndpointChanged, err)
	}
	if err := a.requireScopedXHTTPRuntime(ctx, material.Config); err != nil {
		return nil, nil, nil, err
	}
	document := map[string]any{}
	if json.Unmarshal(material.Config, &document) != nil {
		return nil, nil, nil, errors.New("invalid scoped Xray material")
	}
	endpointHosts := scopedNodeEndpointHosts(document)
	manifest := &proxyNodeManifest{Schema: 1, Engine: "xray", NetworkProfile: plan.NetworkProfileID, Routes: routes, Requests: requests}
	for _, item := range document["outbounds"].([]any)[1:] {
		outbound := item.(map[string]any)
		server := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		host := server["address"].(string)
		addresses, err := a.resolveNodeEndpoint(ctx, host)
		if err != nil {
			return nil, nil, nil, err
		}
		// The following native canary checks this pinned address. Reconcile may
		// retain it only while a fresh system resolve still contains that IP.
		pinned := addresses[0].String()
		server["address"] = pinned
		manifest.Endpoints = append(manifest.Endpoints, proxyNodeEndpoint{Host: host, IP: pinned, Tag: outbound["tag"].(string)})
	}
	data, err := json.Marshal(document)
	return data, endpointHosts, manifest, err
}

func (a *ProxyTunnelAdapter) resolveNodeEndpoint(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if !publicNodeAddresses([]netip.Addr{address}) {
			return nil, ErrNodeEndpointChanged
		}
		return []netip.Addr{address}, nil
	}
	if a.Resolver == nil {
		return nil, ErrNodeEndpointChanged
	}
	addresses, err := a.Resolver(ctx, host)
	if err != nil || !publicNodeAddresses(addresses) {
		return nil, ErrNodeEndpointChanged
	}
	return addresses, nil
}

func (a *ProxyTunnelAdapter) buildEngineCandidate(source []byte, port int) ([]byte, []string, error) {
	if !a.scopedXray {
		return buildProxyCandidate(a.ID(), source, port)
	}
	var doc map[string]any
	if json.Unmarshal(source, &doc) != nil {
		return nil, nil, errors.New("invalid scoped Xray config")
	}
	// Stage admits the NodeStore template; Canary only changes its listener.
	delete(doc, "inbounds")
	doc["inbounds"] = []any{map[string]any{"tag": "rz-engine-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}
	data, err := json.MarshalIndent(doc, "", "  ")
	return data, scopedNodeEndpointHosts(doc), err
}

func scopedNodeTag(id string) string { return "rz-node-" + strings.TrimPrefix(id, "node-")[:16] }

func scopedDomains(values []string) []string {
	var domains []string
	for _, v := range values {
		v = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), ".")), "*.")
		if v != "" && !strings.ContainsAny(v, " /\\\x00") {
			domains = append(domains, v)
		}
	}
	return sortedUnique(domains)
}

func scopedXrayRules(requests []NodeRouteRequest) ([]any, error) {
	bindings := make([]nodestore.RouteBinding, len(requests))
	for i, request := range requests {
		bindings[i] = nodestore.RouteBinding{NodeID: request.NodeID, Domains: request.Domains, Destinations: request.Destinations}
	}
	// LAN sources are unavailable to the engine after the TUN's fixed SOCKS
	// hop. Source-disjoint RPDB cells cannot resolve engine exit ambiguity.
	if err := nodestore.ValidateRouteDestinationOwners(bindings); err != nil {
		return nil, errors.Join(ErrNodeDestinationScope, err)
	}
	var rules []any
	for _, r := range requests {
		if !exactNodeIDPattern.MatchString(r.NodeID) {
			return nil, errors.New("invalid exact node reference")
		}
		domains := scopedDomains(r.Domains)
		var cidrs []string
		for _, value := range r.Destinations {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !publicNodeAddresses([]netip.Addr{prefix.Addr()}) {
				return nil, errors.New("invalid scoped destination")
			}
			cidrs = append(cidrs, prefix.Masked().String())
		}
		cidrs = sortedUnique(cidrs)
		if len(domains)+len(cidrs) == 0 {
			return nil, errors.New("empty node destination scope")
		}
		if len(domains) > 0 {
			for i := range domains {
				domains[i] = "domain:" + domains[i]
			}
			rules = append(rules, map[string]any{"type": "field", "domain": domains, "outboundTag": scopedNodeTag(r.NodeID)})
		}
		if len(cidrs) > 0 {
			rules = append(rules, map[string]any{"type": "field", "ip": cidrs, "outboundTag": scopedNodeTag(r.NodeID)})
		}
	}
	return append(rules, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "rz-node-block"}), nil
}

// A trusted template boundary. User drafts never reach this validator; all
// route rules must exactly match the current NodeStore materialization intent.
func validateScopedXrayConfig(data []byte, requests []NodeRouteRequest, port int) error {
	if !scopedNodeUniqueJSON(data) {
		return errors.New("invalid scoped Xray template")
	}
	var doc struct {
		Log       json.RawMessage   `json:"log"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Routing   json.RawMessage   `json:"routing"`
		Inbounds  json.RawMessage   `json:"inbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || len(data) > 4<<20 {
		return errors.New("invalid scoped Xray template")
	}
	var routes map[string]any
	if json.Unmarshal(doc.Routing, &routes) != nil {
		return errors.New("missing scoped Xray routing")
	}
	wanted, err := scopedXrayRules(requests)
	if err != nil {
		return err
	}
	actual, _ := json.Marshal(routes)
	expected, _ := json.Marshal(map[string]any{"domainStrategy": "AsIs", "rules": wanted})
	if !bytes.Equal(actual, expected) {
		return errors.New("Xray routing differs from exact node scope")
	}
	ids := map[string]bool{}
	for _, r := range requests {
		ids[r.NodeID] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	if len(doc.Outbounds) != len(ordered)+1 {
		return errors.New("unexpected scoped Xray exits")
	}
	var block map[string]any
	_ = json.Unmarshal(doc.Outbounds[0], &block)
	if !reflect.DeepEqual(block, map[string]any{"protocol": "blackhole", "tag": "rz-node-block", "settings": map[string]any{}}) {
		return errors.New("Xray default is not the exact blackhole")
	}
	seenTags := map[string]bool{}
	for i, id := range ordered {
		var outbound map[string]any
		tag := scopedNodeTag(id)
		if seenTags[tag] || json.Unmarshal(doc.Outbounds[i+1], &outbound) != nil || outbound["tag"] != tag {
			return errors.New("Xray exit identity differs")
		}
		seenTags[tag] = true
		// Static-exit validation is used for config admission only, never as a
		// substituted runtime passport for the full routed process.
		projection, _ := json.Marshal(map[string]any{"outbounds": []any{outbound}})
		kind, err := routeidentity.ConfigOutbound("xray", projection)
		clear(projection)
		if err != nil || kind != "vless" {
			return errors.New("scoped Xray has no static VLESS exit")
		}
		if _, err := validateScopedXHTTPOutbound(doc.Outbounds[i+1], outbound); err != nil {
			return err
		}
		settings, ok := outbound["settings"].(map[string]any)
		if !ok {
			return errors.New("invalid Xray server")
		}
		servers, ok := settings["vnext"].([]any)
		if !ok || len(servers) != 1 {
			return errors.New("invalid Xray server")
		}
		server, ok := servers[0].(map[string]any)
		if !ok {
			return errors.New("invalid Xray server")
		}
		host, ok := server["address"].(string)
		if !ok || host == "" {
			return errors.New("invalid Xray endpoint")
		}
	}
	if port == 0 && len(doc.Inbounds) != 0 {
		return errors.New("NodeStore material contains listeners")
	}
	if port != 0 {
		var inbound any
		_ = json.Unmarshal(doc.Inbounds, &inbound)
		want := []any{map[string]any{"tag": "rz-engine-in", "listen": "127.0.0.1", "port": float64(port), "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}
		if !reflect.DeepEqual(inbound, want) {
			return errors.New("scoped Xray listener differs")
		}
	}
	return nil
}

func (a *ProxyTunnelAdapter) readNodeManifest(path string) (proxyNodeManifest, error) {
	data, err := readBoundedSidecar(path)
	var m proxyNodeManifest
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.Schema != 1 || m.Engine != "xray" || len(m.ConfigHash) != 64 || len(m.SidecarHash) != 64 || len(m.Endpoints) == 0 || len(m.Endpoints) > 64 {
		return m, errors.New("invalid scoped node manifest")
	}
	if d.Decode(new(any)) != io.EOF {
		return m, errors.New("trailing scoped manifest")
	}
	if !systemprobe.ValidWANProfileID(m.NetworkProfile) {
		return m, ErrNetworkChanged
	}
	return m, nil
}

func (a *ProxyTunnelAdapter) validateNodeFiles(ctx context.Context, path, engine, sidecar string) (proxyNodeManifest, error) {
	m, err := a.readNodeManifest(path)
	if err != nil {
		return m, err
	}
	config, err := readBoundedProxyConfig(engine)
	if err != nil {
		return m, err
	}
	defer clear(config)
	side, err := readBoundedSidecar(sidecar)
	if err != nil {
		return m, err
	}
	defer clear(side)
	if routeidentity.Hash(config) != m.ConfigHash || routeidentity.Hash(side) != m.SidecarHash {
		return m, errors.New("scoped runtime config digest differs")
	}
	if err := validateScopedXrayConfig(config, m.Requests, a.SOCKSPort); err != nil {
		return m, err
	}
	if err := a.requireScopedXHTTPRuntime(ctx, config); err != nil {
		return m, err
	}
	var document struct {
		Outbounds []struct {
			Tag      string
			Settings struct {
				VNext []struct{ Address string } `json:"vnext"`
			}
		}
	}
	if json.Unmarshal(config, &document) != nil || len(document.Outbounds) != len(m.Endpoints)+1 {
		return m, errors.New("endpoint binding count differs")
	}
	endpoints := map[string]string{}
	for _, outbound := range document.Outbounds[1:] {
		if len(outbound.Settings.VNext) != 1 {
			return m, errors.New("invalid endpoint binding")
		}
		endpoints[outbound.Tag] = outbound.Settings.VNext[0].Address
	}
	for _, endpoint := range m.Endpoints {
		if endpoints[endpoint.Tag] != endpoint.IP || endpoint.IP == "" {
			return m, errors.New("endpoint binding differs from routed process")
		}
		delete(endpoints, endpoint.Tag)
		addresses, err := a.resolveNodeEndpoint(ctx, endpoint.Host)
		found := false
		for _, addr := range addresses {
			if addr.String() == endpoint.IP {
				found = true
			}
		}
		if err != nil || !found {
			return m, ErrNodeEndpointChanged
		}
	}
	if len(endpoints) != 0 {
		return m, errors.New("incomplete scoped endpoint bindings")
	}
	return m, a.checkRouteNetwork(ctx, RoutePlan{NetworkProfileID: m.NetworkProfile})
}

func (a *ProxyTunnelAdapter) validateStagedNodes(ctx context.Context, root string) (proxyNodeManifest, error) {
	return a.validateNodeFiles(ctx, filepath.Join(root, "nodes.staged.json"), filepath.Join(root, "engine.staged.json"), filepath.Join(root, "sidecar.staged.json"))
}

func (a *ProxyTunnelAdapter) checkScopedNodeState(ctx context.Context, plan Plan) (proxyNodeManifest, error) {
	m, err := a.validateNodeFiles(ctx, a.nodeManifestPath(), a.engineConfigPath(), a.sidecarConfigPath())
	if err != nil {
		return m, err
	}
	routes, err := a.scopedRoutes(plan)
	if err != nil {
		return m, err
	}
	requests, err := a.nodeRequests(ctx, routes)
	if err != nil {
		return m, err
	}
	if plan.NetworkProfileID != m.NetworkProfile || !reflect.DeepEqual(routes, m.Routes) || !reflect.DeepEqual(requests, m.Requests) {
		return m, ErrNodeEndpointChanged
	}
	return m, nil
}

// nowUTC is only a compilation timestamp; it never invents a DNS lease.
func nowUTC() time.Time { return time.Now().UTC() }
