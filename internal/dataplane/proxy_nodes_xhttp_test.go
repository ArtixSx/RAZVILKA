package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func nodeXHTTPOutbound(t *testing.T, security string, xhttp bool) []byte {
	t.Helper()
	profile := providerprofile.VLESSProfile{Server: "node.example", Port: 443, UUID: "123e4567-e89b-12d3-a456-426614174000",
		Security: security, Transport: "tcp", ServerName: "front.example", Fingerprint: "chrome"}
	if security == "reality" {
		profile.RealityPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		profile.RealityShortID = "abcd"
	} else {
		profile.ALPN = []string{"h2"}
	}
	if xhttp {
		profile.Transport = "xhttp"
		profile.XHTTP = map[string]any{"type": "xhttp", "host": "front.example", "path": "/xhttp?fixture=1", "mode": "packet-up",
			"extra": map[string]any{"headers": map[string]any{"Authorization": "private-header", "Address": "private-header-value"},
				"sessionPlacement": "query", "sessionKey": "session", "seqPlacement": "query", "seqKey": "seq", "noGRPCHeader": true}}
	}
	config, _, err := providerprofile.CompileXrayConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	var doc struct{ Outbounds []json.RawMessage }
	if json.Unmarshal(config, &doc) != nil || len(doc.Outbounds) != 1 {
		t.Fatal("fixture compiler returned no exact outbound")
	}
	return append([]byte(nil), doc.Outbounds[0]...)
}

func nodeXHTTPMaterial(t *testing.T, requests []NodeRouteRequest, raw []byte) NodeRouteMaterial {
	t.Helper()
	rules, err := scopedXrayRules(requests)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("invalid fixture outbound")
	}
	out["tag"] = scopedNodeTag(requests[0].NodeID)
	doc := map[string]any{"log": map[string]any{"loglevel": "warning", "access": "none"},
		"outbounds": []any{map[string]any{"protocol": "blackhole", "tag": "rz-node-block", "settings": map[string]any{}}, out},
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules}}
	config, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Model the historical recursive metadata collector: consumer may seal
	// this value, but must never send an HTTP header value to a resolver.
	return NodeRouteMaterial{EngineID: "xray", Config: config, EndpointHosts: []string{"node.example", "private-header-value"}}
}

func nodeXHTTPFixture(t *testing.T, security string, xhttp bool) (*ProxyTunnelAdapter, Plan, []byte, *int, *int) {
	t.Helper()
	fixture := scopedXrayTestFixture(t)
	a, plan := fixture.a, fixture.plan
	plan.Routes[0].Domains = []string{"service.example"}
	plan.Routes[0].CIDRs = []string{"9.9.9.9"}
	plan.Routes[0].ProbeURL = "https://service.example/probe"
	outbound := nodeXHTTPOutbound(t, security, xhttp)
	versions, resolutions := new(int), new(int)
	a.nodeXHTTPVersion = func(ctx context.Context, binary string) error {
		*versions++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second || binary != a.engineBinary() {
			t.Fatal("unbounded or different installed runtime version producer")
		}
		return nil
	}
	a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		*resolutions++
		if host == "node.example" {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		if host != "service.example" {
			t.Fatal("private header or unadmitted endpoint reached DNS")
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	a.Runner = nodeRouterForbiddenRunner{}
	a.NodeRoutes = func(_ context.Context, requests []NodeRouteRequest, _ string, _ time.Time) (NodeRouteMaterial, error) {
		return nodeXHTTPMaterial(t, requests, outbound), nil
	}
	return a, plan, outbound, versions, resolutions
}

func TestScopedXHTTPConsumerPreservesTLSRealityExtraAndPinnedNames(t *testing.T) {
	for _, security := range []string{"tls", "reality"} {
		t.Run(security, func(t *testing.T) {
			a, plan, _, versions, resolutions := nodeXHTTPFixture(t, security, true)
			base := a.NodeRoutes
			calls := 0
			a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, at time.Time) (NodeRouteMaterial, error) {
				calls++
				if calls == 1 && (*resolutions != 0 || !reflect.DeepEqual(requests[0].Destinations, []string{"9.9.9.9/32"})) {
					t.Fatal("intent materialization resolved before admission or invented a scope")
				}
				if calls == 2 && *versions != 1 {
					t.Fatal("service DNS preceded the version gate")
				}
				material, err := base(ctx, requests, profile, at)
				requests[0].Domains[0] = "mutated.example"
				requests[0].Destinations[0] = "4.4.4.4/32"
				return material, err
			}
			data, hosts, manifest, err := a.stageScopedXray(context.Background(), plan)
			if err != nil || calls != 2 || *versions != 2 || *resolutions != 2 || !reflect.DeepEqual(hosts, []string{"node.example"}) {
				t.Fatal("exact scoped XHTTP failed", err, calls, *versions, *resolutions)
			}
			var doc map[string]any
			_ = json.Unmarshal(data, &doc)
			out := doc["outbounds"].([]any)[1].(map[string]any)
			server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			stream := out["streamSettings"].(map[string]any)
			xsettings := stream["xhttpSettings"].(map[string]any)
			securitySettings := stream[security+"Settings"].(map[string]any)
			if server["address"] != "1.1.1.1" || securitySettings["serverName"] != "front.example" || stream["network"] != "xhttp" ||
				xsettings["host"] != "front.example" || xsettings["path"] != "/xhttp?fixture=1" || xsettings["extra"].(map[string]any)["headers"].(map[string]any)["Address"] != "private-header-value" ||
				manifest.Endpoints[0].Host != "node.example" || manifest.Requests[0].Domains[0] != "service.example" || plan.Routes[0].Domains[0] != "service.example" {
				t.Fatal("pinned compiler settings or immutable scope changed")
			}
			candidate, endpoints, err := a.buildEngineCandidate(data, a.SOCKSPort)
			if err != nil || !reflect.DeepEqual(endpoints, []string{"1.1.1.1"}) || validateScopedXrayConfig(candidate, manifest.Requests, a.SOCKSPort) != nil {
				t.Fatal("listener construction widened endpoint/scope", err)
			}
		})
	}
}

func TestScopedXHTTPConsumerVersionRefusalPrecedesDNSAndWrites(t *testing.T) {
	for _, mode := range []string{"missing-runtime", "wrong-version", "revoked", "canceled-in-producer", "canceled-before"} {
		t.Run(mode, func(t *testing.T) {
			a, plan, _, versions, resolutions := nodeXHTTPFixture(t, "tls", true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled-before" {
				cancel()
			}
			a.nodeXHTTPVersion = func(context.Context, string) error {
				*versions++
				switch mode {
				case "missing-runtime":
					return ErrExactNodeRuntime
				case "wrong-version":
					return ErrExactNodeUnsupported
				case "revoked":
					return ErrReviewChanged
				default:
					cancel()
					return nil
				}
			}
			root := t.TempDir()
			if err := a.Snapshot(context.Background(), plan, root); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(root, "snapshot.json"))
			if err := a.Stage(ctx, plan, root); err == nil || *resolutions != 0 {
				t.Fatal("runtime refusal reached DNS/stage", err, *resolutions)
			}
			after, _ := os.ReadFile(filepath.Join(root, "snapshot.json"))
			entries, _ := os.ReadDir(root)
			if string(before) != string(after) || len(entries) != 1 {
				t.Fatal("runtime refusal changed transaction files")
			}
		})
	}
}

func TestScopedXHTTPConsumerMaterializationCannotChangeExit(t *testing.T) {
	for _, mode := range []string{"raw-to-xhttp", "uuid", "tls-name", "path", "host-metadata"} {
		t.Run(mode, func(t *testing.T) {
			a, plan, outbound, _, resolutions := nodeXHTTPFixture(t, "tls", mode != "raw-to-xhttp")
			calls := 0
			a.NodeRoutes = func(_ context.Context, requests []NodeRouteRequest, _ string, _ time.Time) (NodeRouteMaterial, error) {
				calls++
				raw := append([]byte(nil), outbound...)
				if calls == 2 {
					switch mode {
					case "raw-to-xhttp":
						raw = nodeXHTTPOutbound(t, "tls", true)
					case "uuid":
						raw = []byte(strings.Replace(string(raw), "123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174001", 1))
					case "tls-name":
						raw = []byte(strings.Replace(string(raw), `"serverName": "front.example"`, `"serverName": "other.example"`, 1))
					case "path":
						raw = []byte(strings.Replace(string(raw), "/xhttp?fixture=1", "/other", 1))
					}
				}
				material := nodeXHTTPMaterial(t, requests, raw)
				if calls == 2 && mode == "host-metadata" {
					material.EndpointHosts = []string{"other.example"}
				}
				return material, nil
			}
			if _, _, _, err := a.stageScopedXray(context.Background(), plan); !errors.Is(err, ErrNodeEndpointChanged) || calls != 2 || *resolutions != 1 {
				t.Fatal("changed material was not fenced before endpoint DNS", mode, err, calls, *resolutions)
			}
		})
	}
}

func TestScopedXHTTPConsumerRejectsUncompiledTransportAndScopeBeforeDNS(t *testing.T) {
	for _, mode := range []string{"download", "vision", "h3", "security-none", "insecure", "unknown-stream", "invalid-network", "proxy-settings", "mux", "duplicate", "false-raw", "routing", "tag", "default", "listener"} {
		t.Run(mode, func(t *testing.T) {
			a, plan, _, versions, resolutions := nodeXHTTPFixture(t, "tls", true)
			base := a.NodeRoutes
			a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, at time.Time) (NodeRouteMaterial, error) {
				material, err := base(ctx, requests, profile, at)
				var doc map[string]any
				_ = json.Unmarshal(material.Config, &doc)
				out := doc["outbounds"].([]any)[1].(map[string]any)
				stream := out["streamSettings"].(map[string]any)
				switch mode {
				case "download":
					stream["xhttpSettings"].(map[string]any)["extra"].(map[string]any)["downloadSettings"] = map[string]any{"address": "other.example"}
				case "vision":
					out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["flow"] = "xtls-rprx-vision"
				case "h3":
					stream["tlsSettings"].(map[string]any)["alpn"] = []string{"h3"}
				case "security-none":
					stream["security"] = "none"
				case "insecure":
					stream["tlsSettings"].(map[string]any)["allowInsecure"] = true
				case "unknown-stream":
					stream["unknown"] = true
				case "invalid-network":
					stream["network"] = true
				case "proxy-settings":
					out["proxySettings"] = map[string]any{"tag": "foreign"}
				case "mux":
					out["mux"] = map[string]any{"enabled": true}
				case "false-raw":
					stream["network"] = "tcp"
				case "routing":
					doc["routing"].(map[string]any)["rules"] = []any{}
				case "tag":
					out["tag"] = "other"
				case "default":
					doc["outbounds"].([]any)[0].(map[string]any)["protocol"] = "freedom"
				case "listener":
					doc["inbounds"] = []any{}
				}
				material.Config, _ = json.Marshal(doc)
				if mode == "duplicate" {
					material.Config = []byte(strings.Replace(string(material.Config), `"network":"xhttp"`, `"network":"xhttp","network":"xhttp"`, 1))
				}
				return material, err
			}
			if _, _, _, err := a.stageScopedXray(context.Background(), plan); err == nil || *versions != 0 || *resolutions != 0 {
				t.Fatal("invalid compiler material reached runtime/DNS", mode, err, *versions, *resolutions)
			}
		})
	}
}

func TestScopedXHTTPConsumerFreshReadbackChecksVersionBeforeDNS(t *testing.T) {
	a, plan, _, versions, resolutions := nodeXHTTPFixture(t, "tls", true)
	data, _, manifest, err := a.stageScopedXray(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := a.buildEngineCandidate(data, a.SOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := []byte(`{}`)
	manifest.ConfigHash, manifest.SidecarHash = routeidentity.Hash(candidate), routeidentity.Hash(sidecar)
	root := t.TempDir()
	manifestPath, enginePath, sidecarPath := filepath.Join(root, "nodes.json"), filepath.Join(root, "engine.json"), filepath.Join(root, "sidecar.json")
	manifestData, _ := json.Marshal(manifest)
	for path, bytes := range map[string][]byte{manifestPath: manifestData, enginePath: candidate, sidecarPath: sidecar} {
		if err := os.WriteFile(path, bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.validateNodeFiles(context.Background(), manifestPath, enginePath, sidecarPath); err != nil || *versions != 3 {
		t.Fatal("fresh exact version was not checked", err, *versions)
	}
	before := *resolutions
	a.nodeXHTTPVersion = func(context.Context, string) error { return ErrExactNodeUnsupported }
	if _, err := a.validateNodeFiles(context.Background(), manifestPath, enginePath, sidecarPath); !errors.Is(err, ErrExactNodeUnsupported) || *resolutions != before {
		t.Fatal("stale capability reached endpoint DNS", err, *resolutions)
	}
}

func TestScopedXHTTPConsumerRAWRetainsAdmissionWithoutVersionProbe(t *testing.T) {
	a, plan, _, versions, _ := nodeXHTTPFixture(t, "tls", false)
	a.nodeXHTTPVersion = func(context.Context, string) error { t.Fatal("RAW called XHTTP runtime producer"); return nil }
	guards := 0
	ctx := WithReviewGuard(context.Background(), func(context.Context) error {
		guards++
		return nil
	})
	if _, _, _, err := a.stageScopedXray(ctx, plan); err != nil || *versions != 0 || guards != 2 {
		t.Fatal("RAW fixture was sent through XHTTP parser", err)
	}
}

func TestScopedXHTTPConsumerRAWMaterializerCannotRevokeAuthorityBeforeDNS(t *testing.T) {
	for _, pass := range []int{1, 2} {
		for _, mode := range []string{"revoke", "cancel-with-nil-guard"} {
			t.Run(strconv.Itoa(pass)+"/"+mode, func(t *testing.T) {
				a, plan, _, versions, resolutions := nodeXHTTPFixture(t, "tls", false)
				// Exercise endpoint DNS/version fencing with explicit IP authority.
				plan.Routes[0].Domains = nil
				materialize, calls, revoked := a.NodeRoutes, 0, false
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx = WithReviewGuard(ctx, func(context.Context) error {
					if revoked {
						if mode == "cancel-with-nil-guard" {
							cancel()
							return nil
						}
						return ErrReviewChanged
					}
					return nil
				})
				a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, at time.Time) (NodeRouteMaterial, error) {
					material, err := materialize(ctx, requests, profile, at)
					calls++
					revoked = calls == pass
					return material, err
				}
				root := t.TempDir()
				if err := a.Snapshot(context.Background(), plan, root); err != nil {
					t.Fatal(err)
				}
				wantErr := ErrReviewChanged
				if mode == "cancel-with-nil-guard" {
					wantErr = context.Canceled
				}
				if err := a.Stage(ctx, plan, root); !errors.Is(err, wantErr) || calls != pass || *versions != 0 || *resolutions != 0 {
					t.Fatal("RAW callback lost caller authority before the next DNS boundary", err, calls, *versions, *resolutions)
				}
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 1 || len(a.Processes.(*proxyFakeProcesses).startSpecs) != 0 {
					t.Fatal("RAW callback refusal wrote staged files or started runtime", err)
				}
			})
		}
	}
}

func TestScopedXHTTPConsumerDoesNotClearProducerBuffersAndBoundsBeforeCopy(t *testing.T) {
	a, plan, outbound, _, _ := nodeXHTTPFixture(t, "tls", true)
	// Exercise endpoint DNS/version fencing with explicit IP authority.
	plan.Routes[0].Domains = nil
	intent, err := a.nodeIntentRequests(plan.Routes)
	if err != nil {
		t.Fatal(err)
	}
	shared := nodeXHTTPMaterial(t, intent, outbound)
	before := append([]byte(nil), shared.Config...)
	hosts := append([]string(nil), shared.EndpointHosts...)
	a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
		return shared, nil
	}
	if _, _, _, err := a.stageScopedXray(context.Background(), plan); err != nil || !reflect.DeepEqual(shared.Config, before) || !reflect.DeepEqual(shared.EndpointHosts, hosts) {
		t.Fatal("consumer erased or rewrote a retained producer buffer", err)
	}
	for _, mode := range []string{"config", "hosts", "host-bytes"} {
		material := shared
		switch mode {
		case "config":
			material.Config = make([]byte, (4<<20)+1)
			material.Config[0] = 'x'
		case "hosts":
			material.EndpointHosts = make([]string, 257)
		case "host-bytes":
			material.EndpointHosts = []string{strings.Repeat("x", 4097)}
		}
		copy, err := copyScopedNodeMaterial(material)
		if err == nil || len(copy.Config) != 0 || material.Config[0] == 0 {
			t.Fatal("oversized producer material copied or cleared", mode, err)
		}
	}
}

func TestScopedXHTTPConsumerMixedNodesGateOncePerBoundary(t *testing.T) {
	a, plan, xhttp, versions, _ := nodeXHTTPFixture(t, "tls", true)
	second := plan.Routes[0]
	second.Resolved = "xray:node-" + strings.Repeat("b", 64)
	second.Domains = []string{"other.example"}
	second.CIDRs = []string{"11.11.11.11/32"}
	plan.Routes = append(plan.Routes, second)
	raw := nodeXHTTPOutbound(t, "tls", false)
	a.NodeRoutes = func(_ context.Context, requests []NodeRouteRequest, _ string, _ time.Time) (NodeRouteMaterial, error) {
		material := nodeXHTTPMaterial(t, requests[:1], xhttp)
		var doc map[string]any
		_ = json.Unmarshal(material.Config, &doc)
		var outbound map[string]any
		_ = json.Unmarshal(raw, &outbound)
		outbound["tag"] = scopedNodeTag(requests[1].NodeID)
		doc["outbounds"] = append(doc["outbounds"].([]any), outbound)
		ordered := doc["outbounds"].([]any)[1:]
		sort.Slice(ordered, func(i, j int) bool {
			return ordered[i].(map[string]any)["tag"].(string) < ordered[j].(map[string]any)["tag"].(string)
		})
		rules, err := scopedXrayRules(requests)
		if err != nil {
			t.Fatal(err)
		}
		doc["routing"].(map[string]any)["rules"] = rules
		material.Config, _ = json.Marshal(doc)
		return material, nil
	}
	a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "node.example":
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		case "service.example":
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		case "other.example":
			return []netip.Addr{netip.MustParseAddr("8.8.4.4")}, nil
		}
		t.Fatal("unadmitted DNS name")
		return nil, nil
	}
	if _, _, manifest, err := a.stageScopedXray(context.Background(), plan); err != nil || *versions != 2 || len(manifest.Endpoints) != 2 {
		t.Fatal("mixed transport lost its single installed-runtime gate", err, *versions)
	}
}

func TestScopedXHTTPConsumerStageRechecksAfterDNSBeforeFirstWrite(t *testing.T) {
	for _, mode := range []string{"late-version", "revoked-before-version", "initial-success-revokes", "late-success-revokes", "initial-guard-cancels", "closing-guard-cancels"} {
		t.Run(mode, func(t *testing.T) {
			a, plan, _, versions, resolutions := nodeXHTTPFixture(t, "tls", true)
			// Exercise endpoint DNS/version fencing with explicit IP authority.
			plan.Routes[0].Domains = nil
			processes := a.Processes.(*proxyFakeProcesses)
			base := &proxyFakeRunner{processes: processes, iface: a.Interface}
			mutations := 0
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				for _, arg := range args {
					if arg == "add" || arg == "del" || arg == "delete" || arg == "replace" || arg == "start" || arg == "stop" {
						mutations++
					}
				}
				return base.Run(ctx, name, args...)
			})
			revoked, materialized := false, false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if revoked {
					return ErrReviewChanged
				}
				if mode == "initial-guard-cancels" && materialized || mode == "closing-guard-cancels" && *versions != 0 {
					cancel()
				}
				return nil
			})
			materialize := a.NodeRoutes
			a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, at time.Time) (NodeRouteMaterial, error) {
				material, err := materialize(ctx, requests, profile, at)
				materialized = true
				if mode == "revoked-before-version" {
					revoked = true
				}
				return material, err
			}
			a.nodeXHTTPVersion = func(context.Context, string) error {
				*versions++
				if mode == "late-version" && *versions == 3 {
					return ErrExactNodeUnsupported
				}
				if mode == "initial-success-revokes" || mode == "late-success-revokes" && *versions == 3 {
					revoked = true
				}
				return nil
			}
			wantErr, wantVersions, wantDNS := ErrReviewChanged, 1, 0
			switch mode {
			case "late-version":
				wantErr, wantVersions, wantDNS = ErrExactNodeUnsupported, 3, 2
			case "revoked-before-version":
				wantVersions = 0
			case "late-success-revokes":
				wantVersions, wantDNS = 3, 2
			case "initial-guard-cancels":
				wantErr, wantVersions = context.Canceled, 0
			case "closing-guard-cancels":
				wantErr = context.Canceled
			}
			root := t.TempDir()
			if err := a.Snapshot(context.Background(), plan, root); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Stage(ctx, plan, root); !errors.Is(err, wantErr) || *versions != wantVersions || *resolutions != wantDNS {
				t.Fatal("version boundary lost authority before DNS/write", err, *versions, *resolutions)
			}
			after, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
			if err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || !reflect.DeepEqual(before, after) || mutations != 0 || len(processes.startSpecs) != 0 {
				t.Fatal("version/authority refusal wrote/staged/activated an effect", err)
			}
		})
	}
}
