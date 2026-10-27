package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// Modes select an installed implementation. They never grant process, interface
// or policy ownership, which still requires the ordinary receipt readbacks.
type proxyXrayMode string

const (
	proxyXrayModeGeneric proxyXrayMode = "generic"
	proxyXrayModeNode    proxyXrayMode = "node"
	proxyXrayModeCold    proxyXrayMode = "cold"
)

var errProxyXrayMode = errors.New("Xray mode cannot be established from frozen intent and complete runtime files")

func proxyXrayModeError() error { return errors.Join(ErrProxyPolicyUnknown, errProxyXrayMode) }

func validProxyXrayMode(mode proxyXrayMode) bool {
	return mode == proxyXrayModeGeneric || mode == proxyXrayModeNode || mode == proxyXrayModeCold
}

func (a *ProxyTunnelAdapter) xrayPlanMode(plan Plan) (proxyXrayMode, error) {
	if a == nil || a.ID() != "xray" {
		return "", proxyXrayModeError()
	}
	// Classify the original routes. RoutePlanFor would silently remove malformed
	// or differently spelled resolved routes before this admission boundary.
	mode, err := proxyXrayRoutesMode(plan.Routes, false)
	if err != nil || mode == proxyXrayModeCold && !slices.Contains(plan.RetiringAdapters, "xray") {
		return "", proxyXrayModeError()
	}
	return mode, nil
}

func proxyXrayFrozenPlanMode(plan RoutePlan) (proxyXrayMode, error) {
	if plan.Adapter != "xray" {
		return "", proxyXrayModeError()
	}
	mode, err := proxyXrayRoutesMode(plan.Routes, true)
	if err != nil || mode == proxyXrayModeCold {
		return "", proxyXrayModeError()
	}
	return mode, nil
}

func proxyXrayRoutesMode(routes []Route, exclusivelyXray bool) (proxyXrayMode, error) {
	if len(routes) > 4096 {
		return "", proxyXrayModeError()
	}
	var mode proxyXrayMode
	count := 0
	for _, route := range routes {
		owned := adapterID(route.Resolved) == "xray"
		// A selected Xray route with a malformed resolution must not disappear
		// merely because adapterID no longer recognizes its resolved value.
		if !owned {
			if exclusivelyXray || strings.HasPrefix(strings.ToLower(strings.TrimSpace(route.Resolved)), "xray") ||
				strings.HasPrefix(strings.ToLower(strings.TrimSpace(route.Selected)), "xray") {
				return "", proxyXrayModeError()
			}
			continue
		}
		current := proxyXrayModeGeneric
		if route.Resolved != "xray" {
			if !strings.HasPrefix(route.Resolved, "xray:") || !exactNodeIDPattern.MatchString(strings.TrimPrefix(route.Resolved, "xray:")) {
				return "", proxyXrayModeError()
			}
			current = proxyXrayModeNode
		}
		if mode != "" && mode != current {
			return "", proxyXrayModeError()
		}
		mode = current
		count++
	}
	if count == 0 {
		// Only a full reviewed Plan can bind retirement to this absence. An
		// adapter-neutral canary scope never admits an empty candidate.
		return proxyXrayModeCold, nil
	}
	if mode == proxyXrayModeNode && count > 64 {
		return "", proxyXrayModeError()
	}
	return mode, nil
}

func (a *ProxyTunnelAdapter) xrayModeView(mode proxyXrayMode) (*ProxyTunnelAdapter, error) {
	if a == nil || a.ID() != "xray" || !validProxyXrayMode(mode) {
		return nil, proxyXrayModeError()
	}
	view := *a
	view.scopedXray = mode == proxyXrayModeNode
	// A view cannot re-enter public dispatch, including an old-mode rollback
	// view for which xrayOperation is intentionally false.
	view.xrayPlanDispatch = false
	return &view, nil
}

type proxyXrayFileImage struct {
	data   []byte
	exists bool
}

func (a *ProxyTunnelAdapter) xraySnapshotPreviousMode(snapshot proxySnapshot) (proxyXrayMode, error) {
	if a == nil || a.ID() != "xray" || snapshot.EngineID != "" && snapshot.EngineID != "xray" ||
		snapshot.SidecarKind != "" && snapshot.SidecarKind != a.effectiveSidecar() ||
		snapshot.CandidateXrayMode != "" && !validProxyXrayMode(proxyXrayMode(snapshot.CandidateXrayMode)) {
		return "", proxyXrayModeError()
	}
	mode, err := a.classifyXrayRuntimeImages(
		proxyXrayFileImage{snapshot.RuntimeEngine, snapshot.RuntimeEngineExists},
		proxyXrayFileImage{snapshot.RuntimeSidecar, snapshot.RuntimeSideExists},
		proxyXrayFileImage{snapshot.NodeManifest, snapshot.NodeManifestExists},
		proxyXrayFileImage{snapshot.NodeInterface, snapshot.NodeInterfaceExists})
	if err != nil || mode == proxyXrayModeCold && (snapshot.EngineWasRunning || snapshot.SidecarWasRunning) ||
		snapshot.PreviousXrayMode != "" && snapshot.PreviousXrayMode != string(mode) {
		return "", proxyXrayModeError()
	}
	// Legacy snapshots have no captured interface lease. Live interface and
	// process proof remains mandatory when restoring an active node runtime.
	return mode, nil
}

// Read-only, bounded and descriptor-anchored. No materializer, resolver, WAN
// observer, process controller, executable or kernel query is called here.
func (a *ProxyTunnelAdapter) currentXrayRuntimeMode(ctx context.Context) (proxyXrayMode, error) {
	if ctx == nil || a == nil || a.ID() != "xray" || a.StateRoot == "" || !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot {
		return "", proxyXrayModeError()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	before, err := os.Lstat(a.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		// This is an absence classification, not permission to create a root.
		if _, closing := os.Lstat(a.StateRoot); !errors.Is(closing, os.ErrNotExist) {
			return "", proxyXrayModeError()
		}
		return proxyXrayModeCold, ctx.Err()
	}
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return "", proxyXrayModeError()
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return "", proxyXrayModeError()
	}
	defer root.Close()
	names := []string{"engine.json", "sidecar.json", "nodes.json", "interface.json"}
	limits := []int64{4 << 20, 128 << 10, 128 << 10, 4096}
	images := make([]proxyXrayFileImage, len(names))
	identities := make([]os.FileInfo, len(names))
	for i, name := range names {
		images[i], identities[i], err = readProxyXrayImage(root, filepath.Join("runtime", name), limits[i])
		if err != nil {
			return "", err
		}
		defer clear(images[i].data)
	}
	mode, err := a.classifyXrayRuntimeImages(images[0], images[1], images[2], images[3])
	if err != nil || mode == proxyXrayModeNode && !images[3].exists {
		if err == nil {
			err = proxyXrayModeError()
		}
		return "", err
	}
	if mode == proxyXrayModeCold && !proxyXrayColdMarkersAbsent(root) {
		return "", proxyXrayModeError()
	}
	// Repeat the entire set after validation, including negative markers. A
	// partial replacement cannot turn an observed node runtime into generic.
	for i, name := range names {
		closing, identity, err := readProxyXrayImage(root, filepath.Join("runtime", name), limits[i])
		if err != nil {
			return "", err
		}
		equal := closing.exists == images[i].exists && bytes.Equal(closing.data, images[i].data) &&
			(!closing.exists || os.SameFile(identities[i], identity))
		clear(closing.data)
		if !equal {
			return "", proxyXrayModeError()
		}
	}
	if mode == proxyXrayModeCold && !proxyXrayColdMarkersAbsent(root) {
		return "", proxyXrayModeError()
	}
	after, err := os.Lstat(a.StateRoot)
	if err != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) {
		return "", proxyXrayModeError()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return mode, nil
}

// Absence is anchored to the same opened root and checked twice. A surviving
// PID marker is uncertainty, never a PID to adopt or a generic Stop grant.
func proxyXrayColdMarkersAbsent(root *ownedfs.Root) bool {
	for _, name := range []string{filepath.Join("runtime", "engine.pid"), filepath.Join("runtime", "sidecar.pid"), "transport.json"} {
		if _, err := root.Stat(name); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func readProxyXrayImage(root *ownedfs.Root, name string, limit int64) (proxyXrayFileImage, os.FileInfo, error) {
	before, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return proxyXrayFileImage{}, nil, nil
	}
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
		return proxyXrayFileImage{}, nil, proxyXrayModeError()
	}
	data, err := root.ReadLimited(name, limit)
	if err != nil {
		return proxyXrayFileImage{}, nil, proxyXrayModeError()
	}
	after, err := root.Stat(name)
	if err != nil || !os.SameFile(before, after) || after.Size() != int64(len(data)) {
		clear(data)
		return proxyXrayFileImage{}, nil, proxyXrayModeError()
	}
	return proxyXrayFileImage{data, true}, after, nil
}

func (a *ProxyTunnelAdapter) classifyXrayRuntimeImages(engine, sidecar, manifest, lease proxyXrayFileImage) (proxyXrayMode, error) {
	images := []proxyXrayFileImage{engine, sidecar, manifest, lease}
	limits := []int{4 << 20, 128 << 10, 128 << 10, 4096}
	for i, image := range images {
		if image.exists != (len(image.data) != 0) || len(image.data) > limits[i] {
			return "", proxyXrayModeError()
		}
	}
	if !engine.exists && !sidecar.exists && !manifest.exists && !lease.exists {
		return proxyXrayModeCold, nil
	}
	if !engine.exists || !sidecar.exists || a.validateXrayModeSidecar(sidecar.data) != nil {
		return "", proxyXrayModeError()
	}
	if !manifest.exists {
		if lease.exists || validateGenericXrayModeConfig(engine.data, a.SOCKSPort) != nil {
			return "", proxyXrayModeError()
		}
		return proxyXrayModeGeneric, nil
	}
	m, err := a.validateXrayModeManifest(manifest.data, engine.data, sidecar.data)
	if err != nil {
		return "", err
	}
	if lease.exists {
		var saved nodeInterfaceLease
		if decodeProxyXrayModeJSON(lease.data, &saved) != nil || saved.Schema != 1 || saved.Interface != a.Interface || saved.Index < 1 ||
			saved.Boot == "" || len(saved.Boot) > 128 || strings.TrimSpace(saved.Boot) != saved.Boot || strings.ContainsAny(saved.Boot, "\x00\r\n") || saved.ConfigHash != m.ConfigHash {
			return "", proxyXrayModeError()
		}
	}
	return proxyXrayModeNode, nil
}

func decodeProxyXrayModeJSON(data []byte, result any) error {
	if !uniqueProxyJSONKeys(data, 4<<20, true) || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return proxyXrayModeError()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(result) != nil || d.Decode(new(any)) != io.EOF {
		return proxyXrayModeError()
	}
	return nil
}

func validateGenericXrayModeConfig(data []byte, port int) error {
	if !scopedNodeUniqueJSON(data) {
		return proxyXrayModeError()
	}
	if _, err := routeidentity.ConfigOutbound("xray", data); err != nil {
		return proxyXrayModeError()
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return proxyXrayModeError()
	}
	listener := []any{map[string]any{"tag": "rz-engine-in", "listen": "127.0.0.1", "port": float64(port), "protocol": "socks", "settings": map[string]any{"udp": true}}}
	if port < 1024 || port > 65535 || !reflect.DeepEqual(doc["inbounds"], listener) ||
		!reflect.DeepEqual(doc["log"], map[string]any{"loglevel": "warning", "access": "none"}) {
		return proxyXrayModeError()
	}
	if _, exists := doc["metrics"]; exists {
		return proxyXrayModeError()
	}
	return nil
}

func (a *ProxyTunnelAdapter) validateXrayModeSidecar(data []byte) error {
	if a.effectiveSidecar() == "hev" {
		expected, err := a.hevConfig()
		if err == nil && bytes.Equal(data, expected) {
			return nil
		}
		return proxyXrayModeError()
	}
	if a.effectiveSidecar() != "sing-box" {
		return proxyXrayModeError()
	}
	var doc any
	if decodeProxyXrayModeJSON(data, &doc) != nil {
		return proxyXrayModeError()
	}
	for _, schema := range []singBoxSidecarSchema{{}, {modernAddress: true}, {modernAddress: true, dnsMode: true}} {
		data, err := buildSOCKSTunnelConfigForSchema(a.Interface, a.TunnelCIDR, a.SOCKSPort, schema)
		var expected any
		if err == nil && json.Unmarshal(data, &expected) == nil && reflect.DeepEqual(doc, expected) {
			return nil
		}
	}
	return proxyXrayModeError()
}

func (a *ProxyTunnelAdapter) validateXrayModeManifest(data, engine, sidecar []byte) (proxyNodeManifest, error) {
	var m proxyNodeManifest
	if decodeProxyXrayModeJSON(data, &m) != nil || m.Schema != 1 || m.Engine != "xray" || !systemprobe.ValidWANProfileID(m.NetworkProfile) ||
		m.ConfigHash != routeidentity.Hash(engine) || m.SidecarHash != routeidentity.Hash(sidecar) ||
		len(m.Routes) == 0 || len(m.Routes) > 64 || len(m.Requests) != len(m.Routes) || len(m.Endpoints) == 0 || len(m.Endpoints) > 64 {
		return m, proxyXrayModeError()
	}
	mode, err := proxyXrayRoutesMode(m.Routes, true)
	if err != nil || mode != proxyXrayModeNode {
		return m, proxyXrayModeError()
	}
	for i, route := range m.Routes {
		r := m.Requests[i]
		id := route.LogicalServiceID
		if id == "" {
			id = route.ServiceID
		}
		if route.ProbeService != nil {
			service, err := FrozenProbeService(route)
			if err != nil || service.ID != id {
				return m, proxyXrayModeError()
			}
		}
		if id == "" || len(id) > 256 || route.ProbeURL == "" || len(route.ProbeURL) > 4096 || len(route.Sources) == 0 && !a.nodeRouterVerifier ||
			r.ServiceID != id || r.NodeID != strings.TrimPrefix(route.Resolved, "xray:") ||
			(len(r.Domains) != 0 || len(route.Domains) != 0) && !reflect.DeepEqual(r.Domains, route.Domains) ||
			len(r.Domains) > 2048 || len(r.Destinations) > 2048 {
			return m, proxyXrayModeError()
		}
		// DNS additions are captured data, not a new resolver call. Literal
		// intent must remain included; the full saved scope is checked below.
		intent, err := (&ProxyTunnelAdapter{}).nodeIntentRequests([]Route{{ServiceID: id, Resolved: route.Resolved, CIDRs: route.CIDRs}})
		if err != nil {
			return m, proxyXrayModeError()
		}
		for _, prefix := range intent[0].Destinations {
			found := false
			for _, saved := range r.Destinations {
				found = found || saved == prefix
			}
			if !found {
				return m, proxyXrayModeError()
			}
		}
	}
	if err := validateScopedXrayConfig(engine, m.Requests, a.SOCKSPort); err != nil {
		return m, proxyXrayModeError()
	}
	var doc struct {
		Outbounds []struct {
			Tag      string
			Settings struct {
				VNext []struct{ Address string } `json:"vnext"`
			}
		}
	}
	if json.Unmarshal(engine, &doc) != nil || len(doc.Outbounds) != len(m.Endpoints)+1 {
		return m, proxyXrayModeError()
	}
	for i, endpoint := range m.Endpoints {
		out := doc.Outbounds[i+1]
		ip, err := netip.ParseAddr(endpoint.IP)
		if err != nil || !publicNodeAddresses([]netip.Addr{ip}) || ip.String() != endpoint.IP || len(out.Settings.VNext) != 1 ||
			endpoint.Tag != out.Tag || endpoint.IP != out.Settings.VNext[0].Address || !validProxyXrayEndpointHost(endpoint.Host) {
			return m, proxyXrayModeError()
		}
	}
	return m, nil
}

func validProxyXrayEndpointHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return publicNodeAddresses([]netip.Addr{ip})
	}
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
