package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func proxyXrayModeFixture(t *testing.T, node bool) (*ProxyTunnelAdapter, proxySnapshot) {
	t.Helper()
	a := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: t.TempDir(), SOCKSPort: 18082, Interface: "rz-xray", TunnelCIDR: "172.31.22.1/30", xrayPlanDispatch: true}
	// Classification must never ask any producer, resolver or external observer.
	a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("classifier invoked runner")
		return nil, nil
	})
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("classifier invoked DNS")
		return nil, nil
	}
	a.FreshProfile = func(context.Context) (string, error) { t.Fatal("classifier invoked WAN observer"); return "", nil }
	a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
		t.Fatal("classifier invoked materializer")
		return NodeRouteMaterial{}, nil
	}
	a.nodeXHTTPVersion = func(context.Context, string) error { t.Fatal("classifier invoked version producer"); return nil }
	remote := map[string]any{"protocol": "vless", "tag": "exit", "settings": map[string]any{"vnext": []any{map[string]any{"address": "1.1.1.1", "port": 443, "users": []any{map[string]any{"id": "123e4567-e89b-12d3-a456-426614174000", "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "node.example"}}}
	var engine, manifest []byte
	if node {
		id := "node-" + strings.Repeat("a", 64)
		request := NodeRouteRequest{ServiceID: "telegram", NodeID: id, Domains: []string{"telegram.org"}, Destinations: []string{"8.8.8.8/32"}}
		route := Route{ServiceID: request.ServiceID, Selected: "xray:" + id, Resolved: "xray:" + id, Domains: request.Domains, CIDRs: request.Destinations, Sources: []string{"192.168.1.25/32"}, ProbeURL: "https://telegram.org/"}
		rules, err := scopedXrayRules([]NodeRouteRequest{request})
		if err != nil {
			t.Fatal(err)
		}
		remote["tag"] = scopedNodeTag(id)
		source, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "warning"}, "outbounds": []any{map[string]any{"protocol": "blackhole", "tag": "rz-node-block", "settings": map[string]any{}}, remote}, "routing": map[string]any{"domainStrategy": "AsIs", "rules": rules}})
		view := *a
		view.scopedXray = true
		engine, _, err = view.buildEngineCandidate(source, a.SOCKSPort)
		if err != nil {
			t.Fatal(err)
		}
		m := proxyNodeManifest{Schema: 1, Engine: "xray", NetworkProfile: executionNetwork, Routes: []Route{route}, Requests: []NodeRouteRequest{request}, Endpoints: []proxyNodeEndpoint{{Host: "node.example", IP: "1.1.1.1", Tag: scopedNodeTag(id)}}}
		manifest, _ = json.Marshal(m)
	} else {
		source, _ := json.Marshal(map[string]any{"outbounds": []any{remote}})
		var err error
		engine, _, err = buildProxyCandidate("xray", source, a.SOCKSPort)
		if err != nil {
			t.Fatal(err)
		}
	}
	side, err := buildSOCKSTunnelConfig(a.Interface, a.TunnelCIDR, a.SOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	if node {
		var m proxyNodeManifest
		_ = json.Unmarshal(manifest, &m)
		m.ConfigHash, m.SidecarHash = routeidentity.Hash(engine), routeidentity.Hash(side)
		manifest, _ = json.Marshal(m)
	}
	return a, proxySnapshot{EngineID: "xray", RuntimeEngine: engine, RuntimeEngineExists: true, RuntimeSidecar: side, RuntimeSideExists: true, NodeManifest: manifest, NodeManifestExists: node}
}

func proxyXrayModeWriteRuntime(t *testing.T, a *ProxyTunnelAdapter, s proxySnapshot) {
	t.Helper()
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	for _, image := range []struct {
		name   string
		data   []byte
		exists bool
	}{{"engine.json", s.RuntimeEngine, s.RuntimeEngineExists}, {"sidecar.json", s.RuntimeSidecar, s.RuntimeSideExists}, {"nodes.json", s.NodeManifest, s.NodeManifestExists}} {
		if image.exists {
			if err := os.WriteFile(filepath.Join(a.runtimeRoot(), image.name), image.data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if s.NodeManifestExists {
		lease, _ := json.Marshal(nodeInterfaceLease{Schema: 1, Boot: "boot-test", Interface: a.Interface, Index: 7, ConfigHash: routeidentity.Hash(s.RuntimeEngine)})
		if err := os.WriteFile(a.nodeInterfacePath(), lease, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProxyXrayModeFrozenPlansRejectMixedMalformedOriginalRoutes(t *testing.T) {
	a, _ := proxyXrayModeFixture(t, false)
	id := "node-" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		routes []Route
		mode   proxyXrayMode
		bad    bool
	}{
		{"generic", []Route{{Resolved: "xray"}, {Resolved: "direct"}}, proxyXrayModeGeneric, false},
		{"node", []Route{{Resolved: "xray:" + id}}, proxyXrayModeNode, false},
		{"empty-candidate", nil, "", true},
		{"mixed", []Route{{Resolved: "xray"}, {Resolved: "xray:" + id}}, "", true},
		{"uppercase", []Route{{Resolved: "XRAY"}}, "", true},
		{"whitespace", []Route{{Resolved: " xray "}}, "", true},
		{"short-id", []Route{{Resolved: "xray:node-123"}}, "", true},
		{"foreign-suffix", []Route{{Resolved: "xray:" + id + ":other"}}, "", true},
		{"missing-resolution", []Route{{Selected: "xray:" + id, Resolved: "malformed"}}, "", true},
		{"malformed-unfiltered-prefix", []Route{{Resolved: "xray/" + id}}, "", true},
		{"hidden-after-filter", []Route{{Resolved: "xray"}, {Selected: "xray", Resolved: "garbage"}}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := a.xrayPlanMode(Plan{Routes: tc.routes})
			if (err != nil) != tc.bad || !tc.bad && mode != tc.mode {
				t.Fatalf("mode=%q err=%v", mode, err)
			}
		})
	}
	if _, err := proxyXrayFrozenPlanMode(RoutePlan{Adapter: "xray", Routes: []Route{{Resolved: "direct"}}}); err == nil {
		t.Fatal("foreign route in frozen Xray scope accepted")
	}
	if _, err := proxyXrayFrozenPlanMode(RoutePlan{Adapter: "sing-box", Routes: []Route{{Resolved: "xray"}}}); err == nil {
		t.Fatal("foreign adapter accepted")
	}
}

func TestProxyXrayModeRetirementRequiresExplicitFullPlanAndValidOriginalRoutes(t *testing.T) {
	a, _ := proxyXrayModeFixture(t, false)
	for _, tc := range []struct {
		name string
		plan Plan
		bad  bool
	}{
		{"retiring-empty", Plan{RetiringAdapters: []string{"xray"}}, false},
		{"retiring-with-other-engine", Plan{RetiringAdapters: []string{"xray"}, Routes: []Route{{Selected: "sing-box", Resolved: "sing-box"}, {Resolved: "direct"}}}, false},
		{"ordinary-empty", Plan{}, true},
		{"active-empty", Plan{Adapters: []string{"xray"}}, true},
		{"other-retirement", Plan{RetiringAdapters: []string{"sing-box"}, Routes: []Route{{Resolved: "sing-box"}}}, true},
		{"noncanonical-retirement", Plan{RetiringAdapters: []string{"XRAY"}}, true},
		{"malformed-retiring-node", Plan{RetiringAdapters: []string{"xray"}, Routes: []Route{{Selected: "xray:node-", Resolved: "xray:node-"}}}, true},
		{"hidden-malformed-retirement", Plan{RetiringAdapters: []string{"xray"}, Routes: []Route{{Selected: "xray", Resolved: "malformed"}, {Resolved: "sing-box"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := a.xrayPlanMode(tc.plan)
			if (err != nil) != tc.bad || !tc.bad && mode != proxyXrayModeCold {
				t.Fatal(mode, err)
			}
		})
	}
	if _, err := proxyXrayFrozenPlanMode(RoutePlan{Adapter: "xray"}); err == nil {
		t.Fatal("empty canary scope admitted retirement without full Plan")
	}
}

func TestProxyXrayModeSnapshotUsesOnlyCapturedPreviousBytes(t *testing.T) {
	for _, node := range []bool{false, true} {
		a, snapshot := proxyXrayModeFixture(t, node)
		wanted, candidate := proxyXrayModeGeneric, proxyXrayModeNode
		if node {
			wanted, candidate = candidate, wanted
		}
		a.scopedXray = !node
		snapshot.CandidateXrayMode = string(candidate)
		// Corrupt current B must never participate in previous-A classification.
		if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(a.engineConfigPath(), []byte("partial B"), 0600); err != nil {
			t.Fatal(err)
		}
		mode, err := a.xraySnapshotPreviousMode(snapshot)
		if err != nil || mode != wanted {
			t.Fatalf("node=%v mode=%q err=%v", node, mode, err)
		}
		snapshot.PreviousXrayMode = string(candidate)
		if _, err := a.xraySnapshotPreviousMode(snapshot); err == nil {
			t.Fatal("enum overrode captured previous bytes")
		}
	}
	a, _ := proxyXrayModeFixture(t, false)
	if mode, err := a.xraySnapshotPreviousMode(proxySnapshot{}); err != nil || mode != proxyXrayModeCold {
		t.Fatal(mode, err)
	}
	if _, err := a.xraySnapshotPreviousMode(proxySnapshot{EngineWasRunning: true}); err == nil {
		t.Fatal("cold captured runtime with a running engine accepted")
	}
}

func TestProxyXrayModeSnapshotNodeCorruptionNeverFallsBack(t *testing.T) {
	for _, mutation := range []string{"missing-manifest", "manifest-duplicate", "manifest-null", "request-owner", "request-domain", "endpoint", "hash", "terminal", "sidecar", "partial", "exists-mismatch", "oversized"} {
		t.Run(mutation, func(t *testing.T) {
			a, s := proxyXrayModeFixture(t, true)
			var m proxyNodeManifest
			_ = json.Unmarshal(s.NodeManifest, &m)
			switch mutation {
			case "missing-manifest":
				s.NodeManifest, s.NodeManifestExists = nil, false
			case "manifest-duplicate":
				s.NodeManifest = append([]byte(`{"schema":1,`), s.NodeManifest[1:]...)
			case "manifest-null":
				s.NodeManifest = []byte("null")
			case "request-owner":
				m.Requests[0].NodeID = "node-" + strings.Repeat("b", 64)
				s.NodeManifest, _ = json.Marshal(m)
			case "request-domain":
				m.Requests[0].Domains = []string{"other.example"}
				s.NodeManifest, _ = json.Marshal(m)
			case "endpoint":
				m.Endpoints[0].IP = "9.9.9.9"
				s.NodeManifest, _ = json.Marshal(m)
			case "hash":
				m.ConfigHash = strings.Repeat("0", 64)
				s.NodeManifest, _ = json.Marshal(m)
			case "terminal":
				s.RuntimeEngine = []byte(strings.Replace(string(s.RuntimeEngine), `"network": "tcp,udp"`, `"network": "tcp"`, 1))
				m.ConfigHash = routeidentity.Hash(s.RuntimeEngine)
				s.NodeManifest, _ = json.Marshal(m)
			case "sidecar":
				s.RuntimeSidecar = []byte(`{"inbounds":[]}`)
				m.SidecarHash = routeidentity.Hash(s.RuntimeSidecar)
				s.NodeManifest, _ = json.Marshal(m)
			case "partial":
				s.RuntimeSidecar, s.RuntimeSideExists = nil, false
			case "exists-mismatch":
				s.NodeManifestExists = false
			case "oversized":
				s.RuntimeEngine = make([]byte, (4<<20)+1)
			}
			if _, err := a.xraySnapshotPreviousMode(s); err == nil {
				t.Fatal("invalid node snapshot accepted")
			}
		})
	}
}

func TestProxyXrayModeCurrentAnchoredRuntimeAndNodeMarkerFences(t *testing.T) {
	for _, node := range []bool{false, true} {
		a, s := proxyXrayModeFixture(t, node)
		proxyXrayModeWriteRuntime(t, a, s)
		want := proxyXrayModeGeneric
		if node {
			want = proxyXrayModeNode
		}
		if mode, err := a.currentXrayRuntimeMode(context.Background()); err != nil || mode != want {
			t.Fatal(mode, err)
		}
		if node {
			lease, _ := json.Marshal(nodeInterfaceLease{Schema: 1, Boot: "boot-test", Interface: a.Interface, Index: 7, ConfigHash: routeidentity.Hash(s.RuntimeEngine)})
			if err := os.WriteFile(a.nodeInterfacePath(), lease, 0600); err != nil {
				t.Fatal(err)
			}
			if mode, err := a.currentXrayRuntimeMode(context.Background()); err != nil || mode != want {
				t.Fatal(mode, err)
			}
		}
		if err := os.WriteFile(a.nodeInterfacePath(), []byte(`{"schema":1}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := a.currentXrayRuntimeMode(context.Background()); err == nil {
			t.Fatal("orphan/corrupt interface marker accepted")
		}
	}
	a, _ := proxyXrayModeFixture(t, false)
	if mode, err := a.currentXrayRuntimeMode(context.Background()); err != nil || mode != proxyXrayModeCold {
		t.Fatal(mode, err)
	}
	if _, err := os.Stat(a.runtimeRoot()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cold reader created runtime root")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.currentXrayRuntimeMode(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := a.currentXrayRuntimeMode(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.nodeManifestPath(), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.currentXrayRuntimeMode(context.Background()); err == nil {
		t.Fatal("orphan node marker became cold")
	}
}

func TestProxyXrayModeSidecarTemplatesAndDetachedViews(t *testing.T) {
	a, s := proxyXrayModeFixture(t, false)
	for _, schema := range []singBoxSidecarSchema{{}, {modernAddress: true}, {modernAddress: true, dnsMode: true}} {
		s.RuntimeSidecar, _ = buildSOCKSTunnelConfigForSchema(a.Interface, a.TunnelCIDR, a.SOCKSPort, schema)
		if mode, err := a.xraySnapshotPreviousMode(s); err != nil || mode != proxyXrayModeGeneric {
			t.Fatal(mode, err)
		}
	}
	a.SidecarKind = "hev"
	s.SidecarKind = "hev"
	s.RuntimeSidecar, _ = a.hevConfig()
	if mode, err := a.xraySnapshotPreviousMode(s); err != nil || mode != proxyXrayModeGeneric {
		t.Fatal(mode, err)
	}
	s.RuntimeSidecar = []byte("tunnel:\n  name: rz-xray\n")
	if _, err := a.xraySnapshotPreviousMode(s); err == nil {
		t.Fatal("foreign HEV YAML accepted")
	}
	a.nodeRouterVerifier = true
	view, err := a.xrayModeView(proxyXrayModeNode)
	if err != nil || !view.scopedXray || view.xrayPlanDispatch || !view.nodeRouterVerifier || view == a {
		t.Fatal(view, err)
	}
	view.Interface = "other"
	if a.scopedXray || !a.xrayPlanDispatch || a.Interface == "other" {
		t.Fatal("view changed registered startup owner")
	}
}

func TestProxyXrayModeCIDROnlyCapturedNodeAndStrictGeneric(t *testing.T) {
	a, s := proxyXrayModeFixture(t, true)
	var m proxyNodeManifest
	_ = json.Unmarshal(s.NodeManifest, &m)
	m.Routes[0].Domains = nil
	m.Requests[0].Domains = []string{}
	rules, err := scopedXrayRules(m.Requests)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(s.RuntimeEngine, &doc)
	doc["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": rules}
	s.RuntimeEngine, _ = json.Marshal(doc)
	m.ConfigHash = routeidentity.Hash(s.RuntimeEngine)
	s.NodeManifest, _ = json.Marshal(m)
	if mode, err := a.xraySnapshotPreviousMode(s); err != nil || mode != proxyXrayModeNode {
		t.Fatal(mode, err)
	}

	for _, cut := range []string{"duplicate", "listener", "node-listener", "dynamic-api", "orphan-manifest"} {
		t.Run(cut, func(t *testing.T) {
			a, s := proxyXrayModeFixture(t, false)
			switch cut {
			case "duplicate":
				s.RuntimeEngine = append([]byte(`{"outbounds":[],`), s.RuntimeEngine[1:]...)
			case "listener":
				s.RuntimeEngine = []byte(strings.Replace(string(s.RuntimeEngine), "127.0.0.1", "0.0.0.0", 1))
			case "node-listener":
				s.RuntimeEngine = []byte(strings.Replace(string(s.RuntimeEngine), `"udp": true`, `"udp": false`, 1))
			case "dynamic-api":
				s.RuntimeEngine = append([]byte(`{"api":{},`), s.RuntimeEngine[1:]...)
			case "orphan-manifest":
				s.NodeManifest, s.NodeManifestExists = []byte(`{}`), true
			}
			if _, err := a.xraySnapshotPreviousMode(s); err == nil {
				t.Fatal("invalid generic runtime accepted")
			}
		})
	}
}

func TestProxyXrayModeCurrentRefusesUnsafeAndPartialFileShapes(t *testing.T) {
	for _, cut := range []string{"missing-sidecar", "missing-manifest", "missing-interface", "oversized", "directory", "sidecar-unknown", "interface-duplicate"} {
		t.Run(cut, func(t *testing.T) {
			a, s := proxyXrayModeFixture(t, true)
			proxyXrayModeWriteRuntime(t, a, s)
			switch cut {
			case "missing-sidecar":
				if err := os.Remove(a.sidecarConfigPath()); err != nil {
					t.Fatal(err)
				}
			case "missing-manifest":
				if err := os.Remove(a.nodeManifestPath()); err != nil {
					t.Fatal(err)
				}
			case "missing-interface":
				if err := os.Remove(a.nodeInterfacePath()); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(a.nodeManifestPath(), make([]byte, (128<<10)+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(a.engineConfigPath()); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(a.engineConfigPath(), 0700); err != nil {
					t.Fatal(err)
				}
			case "sidecar-unknown":
				if err := os.WriteFile(a.sidecarConfigPath(), append([]byte(`{"unknown":true,`), s.RuntimeSidecar[1:]...), 0600); err != nil {
					t.Fatal(err)
				}
			case "interface-duplicate":
				if err := os.WriteFile(a.nodeInterfacePath(), []byte(`{"schema":1,"schema":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.currentXrayRuntimeMode(context.Background()); err == nil {
				t.Fatal("unsafe/partial file set accepted")
			}
		})
	}
	a, _ := proxyXrayModeFixture(t, false)
	a.StateRoot = filepath.Join(a.StateRoot, "never-created")
	if mode, err := a.currentXrayRuntimeMode(context.Background()); err != nil || mode != proxyXrayModeCold {
		t.Fatal(mode, err)
	}
	if _, err := os.Lstat(a.StateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only mode created state root")
	}
}

type proxyXrayModeNoProcessCalls struct{ t *testing.T }

func (p proxyXrayModeNoProcessCalls) Start(context.Context, ProcessSpec) error {
	p.t.Fatal("classifier started process")
	return nil
}
func (p proxyXrayModeNoProcessCalls) Stop(context.Context, ProcessSpec) error {
	p.t.Fatal("classifier stopped process")
	return nil
}
func (p proxyXrayModeNoProcessCalls) Running(ProcessSpec) bool {
	p.t.Fatal("classifier queried process")
	return false
}

func TestProxyXrayModeColdRefusesSurvivingPIDOrTransportWithoutProcessReads(t *testing.T) {
	for _, marker := range []string{filepath.Join("runtime", "engine.pid"), filepath.Join("runtime", "sidecar.pid"), "transport.json"} {
		t.Run(marker, func(t *testing.T) {
			a, _ := proxyXrayModeFixture(t, false)
			a.Processes = proxyXrayModeNoProcessCalls{t}
			path := filepath.Join(a.StateRoot, marker)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			// Deliberately not decoded. Even a syntactically valid owned PID
			// filename cannot promote unknown cold history to a generic owner.
			original := []byte("1234\n")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := a.currentXrayRuntimeMode(context.Background()); !errors.Is(err, ErrProxyPolicyUnknown) {
				t.Fatal("surviving marker became cold", err)
			}
			retained, err := os.ReadFile(path)
			if err != nil || string(retained) != string(original) {
				t.Fatal("classifier changed retained marker", err)
			}
		})
	}
	// Captured cold history is independent of the current B markers and still
	// uses its own runtime flags; no current PID can authorize its restoration.
	a, _ := proxyXrayModeFixture(t, false)
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.runtimeRoot(), "engine.pid"), []byte("1234"), 0600); err != nil {
		t.Fatal(err)
	}
	if mode, err := a.xraySnapshotPreviousMode(proxySnapshot{}); err != nil || mode != proxyXrayModeCold {
		t.Fatal(mode, err)
	}
}
