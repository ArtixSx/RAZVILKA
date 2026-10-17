package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type scopedXrayFixture struct {
	a         *ProxyTunnelAdapter
	plan      Plan
	processes *proxyFakeProcesses
	runner    *proxyFakeRunner
	store     *nodestore.Store
	endpoint  netip.Addr
	identity  int
}

func privateScopedXrayFixtureDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func scopedXrayTestFixture(t *testing.T) *scopedXrayFixture {
	t.Helper()
	ctx := context.Background()
	nodesRoot := privateScopedXrayFixtureDir(t)
	store, err := nodestore.Open(nodesRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	snapshot, err := store.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls&sni=front.example", now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	_, err = store.RecordCheck(ctx, id, nodestore.CheckRecord{ProbeID: "unit-pass", ServiceID: "telegram", NetworkProfile: executionNetwork, RoutePathID: "xray:" + id, TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	materializer := func(ctx context.Context, requests []NodeRouteRequest, profile string, now time.Time) (NodeRouteMaterial, error) {
		var bindings []nodestore.RouteBinding
		for _, r := range requests {
			bindings = append(bindings, nodestore.RouteBinding{ServiceID: r.ServiceID, NodeID: r.NodeID, NetworkProfile: profile, Domains: r.Domains, Destinations: r.Destinations})
		}
		material, err := store.MaterializeXray(ctx, bindings, now)
		return NodeRouteMaterial{EngineID: material.EngineID, Config: material.Config, EndpointHosts: material.EndpointHosts}, err
	}
	a, err := NewScopedXrayTunnelAdapter(engineconfig.New(privateScopedXrayFixtureDir(t), privateScopedXrayFixtureDir(t)), privateScopedXrayFixtureDir(t), materializer)
	if err != nil {
		t.Fatal(err)
	}
	f := &scopedXrayFixture{a: a, store: store, endpoint: netip.MustParseAddr("1.1.1.1"), identity: 1}
	f.processes = &proxyFakeProcesses{running: map[string]bool{}}
	f.runner = &proxyFakeRunner{processes: f.processes, iface: a.Interface}
	a.EngineBin, a.SidecarBin, a.IP, a.IPTables, a.IP6Tables = "xray", "sing-box", "ip", "iptables", "ip6tables"
	a.Processes = f.processes
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if name == "ip" && joined == "link show dev "+a.Interface {
			if f.processes.running["xray-tun"] {
				return []byte(a.Interface + ": UP"), nil
			}
			return nil, errors.New("not found")
		}
		if name == "ip" && joined == "-j link show" {
			if f.processes.running["xray-tun"] {
				return []byte(`[{"ifindex":77,"ifname":"` + a.Interface + `"}]`), nil
			}
			return []byte(`[]`), nil
		}
		if name == "ip" && joined == "-j link show dev "+a.Interface {
			if f.processes.running["xray-tun"] {
				return []byte(`[{"ifindex":77,"ifname":"` + a.Interface + `"}]`), nil
			}
			return nil, errors.New("not found")
		}
		if name == "ip" && joined == "route get 192.168.1.26" {
			return []byte("192.168.1.26 dev br0 src 192.168.1.1"), nil
		}
		if name == "ip" && joined == "route show table main match 192.168.1.26/32" {
			return []byte("192.168.1.0/24 dev br0 proto kernel scope link src 192.168.1.1"), nil
		}
		if name == "ip" && strings.Contains(joined, "iif br0") {
			if strings.Contains(joined, "from 192.168.1.25 ") {
				return []byte("8.8.8.8 dev " + a.Interface), nil
			}
			return []byte("8.8.8.8 dev wan0"), nil
		}
		return f.runner.Run(ctx, name, args...)
	})
	a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	a.bootIdentity = func() (string, error) { return "boot-test", nil }
	a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "node.example" {
			return []netip.Addr{f.endpoint}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	a.SOCKSProbe = func(context.Context, string) error { return nil }
	a.CanaryProbe = func(context.Context, string, string) error { return nil }
	a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { return nil }
	a.nodeRuntimeIdentity = func(spec ProcessSpec, address string) (string, error) {
		if !f.processes.Running(spec) {
			return "", errors.New("dead")
		}
		data, err := os.ReadFile(spec.MatchArg)
		if err != nil {
			return "", err
		}
		return spec.ID + ":" + strconv.Itoa(f.identity) + ":" + routeidentity.Hash(data), nil
	}
	a.NodeTUNProbe = func(_ context.Context, r NodeTUNRequest) (NodeTUNObservation, error) {
		return NodeTUNObservation{RuntimeID: r.RuntimeID, SelectedSource: netip.MustParseAddr("192.168.1.25"), ControlSource: netip.MustParseAddr("192.168.1.26"), SelectedEgress: netip.MustParseAddr("9.9.9.9"), ControlEgress: netip.MustParseAddr("1.0.0.1"), ServiceAccepted: true}, nil
	}
	f.plan = Plan{NetworkProfileID: executionNetwork, Routes: []Route{{ServiceID: "telegram", ServiceName: "Telegram", Selected: "xray:" + id, Resolved: "xray:" + id, CIDRs: []string{"149.154.160.0/20"}, Sources: []string{"192.168.1.25/32"}, ProbeURL: "https://telegram.org/"}}}
	return f
}

func stageScopedFixture(t *testing.T, f *scopedXrayFixture) string {
	t.Helper()
	root := privateScopedXrayFixtureDir(t)
	ctx := context.Background()
	for _, step := range []func(context.Context, Plan, string) error{f.a.Snapshot, f.a.Stage, f.a.Validate} {
		if err := step(ctx, f.plan, root); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.Canary(ctx, f.plan.RoutePlanFor("xray"), root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScopedXrayLifecycleRetainsEngineAndVerifiedRollback(t *testing.T) {
	f := scopedXrayTestFixture(t)
	a := f.a
	ctx := context.Background()
	root := stageScopedFixture(t, f)
	for _, step := range []func(context.Context, Plan, string) error{a.Activate, a.Health, a.Commit} {
		if err := step(ctx, f.plan, root); err != nil {
			t.Fatal(err)
		}
	}
	m, err := a.checkScopedNodeState(ctx, f.plan)
	if err != nil || m.Engine != "xray" || m.Routes[0].Resolved != f.plan.Routes[0].Resolved {
		t.Fatal(m, err)
	}
	if !a.sidecarProcess().RouteProof {
		t.Fatal("sidecar lacks launch receipt")
	}
	transaction := stageScopedFixture(t, f)
	if err := a.Activate(ctx, f.plan, transaction); err != nil {
		t.Fatal(err)
	}
	delete(f.processes.running, "xray-tun")
	if err := a.Health(ctx, f.plan, transaction); err == nil {
		t.Fatal("dead sidecar accepted")
	}
	if err := a.Rollback(ctx, f.plan, transaction); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.VerifyRollback(ctx, f.plan, transaction); err != nil || !ok {
		t.Fatal("rollback unverified", ok, err)
	}
	if err := a.CommittedNodeHealth(ctx, f.plan); err != nil {
		t.Fatal(err)
	}
	delete(f.processes.running, "xray-tun")
	if err := a.Reconcile(ctx, f.plan); err != nil {
		t.Fatal("sidecar repair failed", err)
	}
	if err := a.CommittedNodeHealth(ctx, f.plan); err != nil {
		t.Fatal(err)
	}
}

func TestScopedXrayRejectsEndpointChangeBeforeLKGMutation(t *testing.T) {
	f := scopedXrayTestFixture(t)
	a := f.a
	ctx := context.Background()
	root := stageScopedFixture(t, f)
	for _, step := range []func(context.Context, Plan, string) error{a.Activate, a.Health, a.Commit} {
		if err := step(ctx, f.plan, root); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadFile(a.engineConfigPath())
	starts := len(f.processes.startSpecs)
	f.endpoint = netip.MustParseAddr("1.0.0.1")
	if err := a.Reconcile(ctx, f.plan); !errors.Is(err, ErrNodeEndpointChanged) {
		t.Fatal(err)
	}
	if _, err := a.RefreshPolicy(ctx, f.plan); !errors.Is(err, ErrNodeEndpointChanged) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(a.engineConfigPath())
	if string(before) != string(after) || len(f.processes.startSpecs) != starts || !f.processes.running["xray-tun"] {
		t.Fatal("stale endpoint changed LKG")
	}
}

func TestScopedXrayTUNProofAndIdentityFailuresCannotCommit(t *testing.T) {
	for _, mode := range []string{"missing-proof", "same-egress", "wrong-client", "control-selected", "identity-change", "config-change", "manifest-endpoint-change"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			a := f.a
			ctx := context.Background()
			root := stageScopedFixture(t, f)
			if err := a.Activate(ctx, f.plan, root); err != nil {
				t.Fatal(err)
			}
			probe := a.NodeTUNProbe
			if mode == "missing-proof" {
				a.NodeTUNProbe = nil
			} else {
				a.NodeTUNProbe = func(ctx context.Context, r NodeTUNRequest) (NodeTUNObservation, error) {
					o, e := probe(ctx, r)
					switch mode {
					case "same-egress":
						o.ControlEgress = o.SelectedEgress
					case "wrong-client":
						o.SelectedSource = netip.MustParseAddr("192.168.1.26")
					case "control-selected":
						o.ControlSource = o.SelectedSource
					case "identity-change":
						f.identity++
					case "config-change":
						_ = os.WriteFile(a.engineConfigPath(), []byte("{}"), 0600)
					}
					return o, e
				}
			}
			if mode == "manifest-endpoint-change" {
				m, err := a.readNodeManifest(a.nodeManifestPath())
				if err != nil {
					t.Fatal(err)
				}
				m.Endpoints[0].IP = "8.8.8.8"
				b, _ := json.Marshal(m)
				_ = os.WriteFile(a.nodeManifestPath(), b, 0600)
			}
			if err := a.Commit(ctx, f.plan, root); err == nil {
				t.Fatal("unproved TUN committed")
			}
			if regularFile(a.policyPath()) {
				t.Fatal("failed health wrote commit journal")
			}
		})
	}
}

func TestScopedXrayRejectsDraftWrongEngineAndBlackholeMutation(t *testing.T) {
	f := scopedXrayTestFixture(t)
	a := f.a
	ctx := context.Background()
	plan := f.plan
	plan.EngineDrafts = []string{"xray/main"}
	root := filepath.Join(t.TempDir(), "absent")
	if err := a.Snapshot(ctx, plan, root); err == nil {
		t.Fatal("accepted draft authority")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("draft refusal wrote state")
	}
	base := a.NodeRoutes
	for _, mode := range []string{"wrong-engine", "freedom-default", "extra-route", "listener"} {
		t.Run(mode, func(t *testing.T) {
			a.NodeRoutes = func(ctx context.Context, r []NodeRouteRequest, p string, now time.Time) (NodeRouteMaterial, error) {
				m, e := base(ctx, r, p, now)
				switch mode {
				case "wrong-engine":
					m.EngineID = "sing-box"
				case "freedom-default":
					m.Config = []byte(strings.Replace(string(m.Config), "blackhole", "freedom", 1))
				case "extra-route":
					var d map[string]any
					_ = json.Unmarshal(m.Config, &d)
					d["routing"].(map[string]any)["balancers"] = []any{}
					m.Config, _ = json.Marshal(d)
				case "listener":
					var d map[string]any
					_ = json.Unmarshal(m.Config, &d)
					d["inbounds"] = []any{}
					m.Config, _ = json.Marshal(d)
				}
				return m, e
			}
			transaction := t.TempDir()
			if err := a.Snapshot(ctx, f.plan, transaction); err != nil {
				t.Fatal(err)
			}
			if err := a.Stage(ctx, f.plan, transaction); err == nil {
				t.Fatal("unsafe material staged")
			}
			if len(f.processes.startSpecs) != 0 {
				t.Fatal("refusal started runtime")
			}
		})
	}
}

func TestScopedXrayInterfaceReplacementAndUnreadableInventoryCannotAuthorizeCleanup(t *testing.T) {
	for _, mode := range []string{"replacement", "unreadable-inventory", "present-but-unreadable"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			ctx := context.Background()
			root := stageScopedFixture(t, f)
			for _, step := range []func(context.Context, Plan, string) error{f.a.Activate, f.a.Health, f.a.Commit} {
				if err := step(ctx, f.plan, root); err != nil {
					t.Fatal(err)
				}
			}
			previous := f.a.Runner
			deleted := false
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				if name == "ip" && command == "link delete dev "+f.a.Interface {
					deleted = true
				}
				if name == "ip" && command == "-j link show dev "+f.a.Interface {
					if mode == "replacement" {
						return []byte(`[{"ifindex":88,"ifname":"` + f.a.Interface + `"}]`), nil
					}
					return nil, errors.New("read denied")
				}
				if name == "ip" && command == "-j link show" {
					if mode == "present-but-unreadable" {
						return []byte(`[{"ifindex":77,"ifname":"` + f.a.Interface + `"}]`), nil
					}
					return nil, errors.New("inventory unavailable")
				}
				return previous.Run(ctx, name, args...)
			})
			if err := f.a.CommittedNodeHealth(ctx, f.plan); err == nil {
				t.Fatal("unknown interface accepted")
			}
			if err := f.a.Deactivate(ctx); err == nil {
				t.Fatal("unknown interface reported removed")
			}
			if deleted {
				t.Fatal("foreign/unknown ifindex deleted")
			}
			if !regularFile(f.a.nodeInterfacePath()) || !regularFile(f.a.engineConfigPath()) {
				t.Fatal("cleanup discarded its ownership fence")
			}
		})
	}
}
