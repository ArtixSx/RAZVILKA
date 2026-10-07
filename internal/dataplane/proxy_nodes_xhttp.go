package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func cloneScopedNodeRequests(requests []NodeRouteRequest) []NodeRouteRequest {
	copy := make([]NodeRouteRequest, len(requests))
	for i, request := range requests {
		copy[i] = request
		copy[i].Domains = append([]string(nil), request.Domains...)
		copy[i].Destinations = append([]string(nil), request.Destinations...)
	}
	return copy
}

// Producers may retain their buffers. Check aggregate bounds before copying,
// and erase only this consumer's private copy when compilation finishes.
func copyScopedNodeMaterial(material NodeRouteMaterial) (NodeRouteMaterial, error) {
	if material.EngineID != "xray" || len(material.Config) == 0 || len(material.Config) > 4<<20 || len(material.EndpointHosts) > 256 {
		return NodeRouteMaterial{}, ErrExactNodeUnsupported
	}
	for _, host := range material.EndpointHosts {
		if len(host) > 4096 || strings.ContainsRune(host, '\x00') {
			return NodeRouteMaterial{}, ErrExactNodeUnsupported
		}
	}
	material.Config = append([]byte(nil), material.Config...)
	material.EndpointHosts = append([]string(nil), material.EndpointHosts...)
	return material, nil
}

// Intent requests contain only the sealed scope. Materialization is an in-memory
// compiler/eligibility check; service and endpoint resolution come afterwards.
func (a *ProxyTunnelAdapter) nodeIntentRequests(routes []Route) ([]NodeRouteRequest, error) {
	requests := make([]NodeRouteRequest, 0, len(routes))
	for _, route := range routes {
		serviceID, err := a.nodeRequestServiceID(route)
		if err != nil {
			return nil, err
		}
		var destinations []string
		for _, value := range route.CIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil || address.Is4In6() {
					return nil, ErrNodeEndpointChanged
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			destinations = append(destinations, prefix.Masked().String())
		}
		requests = append(requests, NodeRouteRequest{ServiceID: serviceID, NodeID: strings.TrimPrefix(route.Resolved, "xray:"),
			Domains: append([]string(nil), route.Domains...), Destinations: sortedUnique(destinations)})
	}
	return requests, nil
}

func (a *ProxyTunnelAdapter) nodeRequestServiceID(route Route) (string, error) {
	if a.nodeRouterVerifier || route.LogicalServiceID != "" {
		service, err := FrozenProbeService(route)
		if err != nil {
			return "", err
		}
		return service.ID, nil
	}
	return route.ServiceID, nil
}

// The original bytes reach the authoritative importer so duplicate/unknown
// XHTTP auth, security and transport fields cannot disappear in map decoding.
// RAW/TCP keeps its existing static-exit admission and never enters this parser.
func validateScopedXHTTPOutbound(raw json.RawMessage, outbound map[string]any) (bool, error) {
	stream, _ := outbound["streamSettings"].(map[string]any)
	network, text := stream["network"].(string)
	if _, exists := stream["network"]; exists && !text {
		return false, ErrExactNodeUnsupported
	}
	if network != "xhttp" && network != "splithttp" {
		_, xsettings := stream["xhttpSettings"]
		_, ssettings := stream["splithttpSettings"]
		if xsettings || ssettings || network != "" && network != "tcp" && network != "raw" {
			return false, ErrExactNodeUnsupported
		}
		return false, nil
	}
	settings, ok := stream["xhttpSettings"].(map[string]any)
	if network != "xhttp" || !ok || providerprofile.ValidateXrayXHTTPSettings(settings) != nil {
		return false, ErrExactNodeUnsupported
	}
	envelope := append([]byte(`{"outbounds":[`), raw...)
	envelope = append(envelope, ']', '}')
	defer clear(envelope)
	compiled, err := providerprofile.ParseXrayProfile(string(envelope), 0)
	defer clear(compiled.Config)
	if err != nil {
		return false, ErrExactNodeUnsupported
	}
	var result struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(compiled.Config, &result) != nil || len(result.Outbounds) != 1 {
		return false, ErrExactNodeUnsupported
	}
	result.Outbounds[0]["tag"] = outbound["tag"]
	if !reflect.DeepEqual(result.Outbounds[0], outbound) {
		return false, ErrExactNodeUnsupported
	}
	return true, nil
}

// A bounded immutable seal spans the two materializer calls. Only routing may
// change when service DNS adds literal destinations; exits and host metadata may
// not change their transport, credentials, TLS name, path or alternate owner.
func scopedNodeMaterialSeal(material NodeRouteMaterial) (string, error) {
	if material.EngineID != "xray" || len(material.Config) == 0 || len(material.Config) > 4<<20 || len(material.EndpointHosts) > 256 {
		return "", ErrExactNodeUnsupported
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(material.Config, &doc) != nil || len(doc.Outbounds) < 2 || len(doc.Outbounds) > 65 {
		return "", ErrExactNodeUnsupported
	}
	for _, host := range material.EndpointHosts {
		if len(host) > 4096 || strings.ContainsRune(host, '\x00') {
			return "", ErrExactNodeUnsupported
		}
	}
	data, err := json.Marshal(struct {
		Outbounds []map[string]any `json:"outbounds"`
		Hosts     []string         `json:"hosts"`
	}{doc.Outbounds, sortedUnique(material.EndpointHosts)})
	if err != nil {
		return "", ErrExactNodeUnsupported
	}
	defer clear(data)
	return routeidentity.Hash(data), nil
}

// Scoped endpoint authority comes only from the compiler's one vnext server.
// HTTP header names/values inside XHTTP extra never become resolver inputs.
func scopedNodeEndpointHosts(document map[string]any) []string {
	var hosts []string
	outbounds, _ := document["outbounds"].([]any)
	for _, value := range outbounds {
		outbound, _ := value.(map[string]any)
		if outbound["protocol"] != "vless" {
			continue
		}
		settings, _ := outbound["settings"].(map[string]any)
		servers, _ := settings["vnext"].([]any)
		if len(servers) == 1 {
			server, _ := servers[0].(map[string]any)
			if host, ok := server["address"].(string); ok {
				hosts = append(hosts, host)
			}
		}
	}
	return sortedUnique(hosts)
}

func (a *ProxyTunnelAdapter) requireScopedXHTTPRuntime(ctx context.Context, data []byte) error {
	if ctx == nil || a == nil || len(data) == 0 || len(data) > 4<<20 {
		return ErrExactNodeUnsupported
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if json.Unmarshal(data, &doc) != nil || len(doc.Outbounds) < 2 || len(doc.Outbounds) > 65 {
		return ErrExactNodeUnsupported
	}
	xhttp := false
	for _, raw := range doc.Outbounds[1:] {
		var out map[string]any
		if json.Unmarshal(raw, &out) != nil {
			return ErrExactNodeUnsupported
		}
		uses, err := validateScopedXHTTPOutbound(raw, out)
		if err != nil {
			return err
		}
		xhttp = xhttp || uses
	}
	if !xhttp {
		return ctx.Err()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := checkAddressRefreshAuthority(probeCtx); err != nil {
		return err
	}
	if err := probeCtx.Err(); err != nil {
		return err
	}
	var err error
	if a.nodeXHTTPVersion != nil {
		err = a.nodeXHTTPVersion(probeCtx, a.engineBinary())
	} else {
		var supported bool
		supported, err = exactXHTTPRuntimeVersion(probeCtx, a.engineBinary())
		if err != nil {
			err = errors.Join(ErrExactNodeRuntime, err)
		} else if !supported {
			err = ErrExactNodeUnsupported
		}
	}
	if authorityErr := checkAddressRefreshAuthority(probeCtx); authorityErr != nil {
		err = errors.Join(err, authorityErr)
	}
	if probeCtx.Err() != nil {
		return probeCtx.Err()
	}
	return err
}

// Duplicate keys are ambiguous execution intent even if a decoder keeps the
// last value. This checks only JSON syntax/uniqueness, not a second schema.
func scopedNodeUniqueJSON(data []byte) bool {
	return uniqueProxyJSON(data, 4<<20)
}

func uniqueProxyJSON(data []byte, maxBytes int) bool {
	return uniqueProxyJSONKeys(data, maxBytes, false)
}

func uniqueProxyJSONKeys(data []byte, maxBytes int, foldKeys bool) bool {
	if len(data) == 0 || len(data) > maxBytes {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if foldKeys {
					name = strings.ToLower(name)
				}
				if err != nil || !ok || seen[name] || !value(depth+1) {
					return false
				}
				seen[name] = true
			}
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		closing, err := d.Token()
		return err == nil && (delim == '{' && closing == json.Delim('}') || delim == '[' && closing == json.Delim(']'))
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
