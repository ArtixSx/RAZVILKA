package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

type managedXraySelectorFixture struct {
	a       *App
	runtime *ManagedXraySelectedTCPListRuntime
	policy  *managedListPolicyOwner
	adapter *dataplane.ProxyTunnelAdapter
	node    string
	root    string
	cancel  context.CancelFunc
}

// The NodeStore, import, factory and Manager registration are real objects.
// Startup owner topology, installed inventory, WAN and recorded health are
// portable models. No native constructor, process, probe or Apply grant runs.
func newManagedXraySelectorFixture(t *testing.T) *managedXraySelectorFixture {
	t.Helper()
	f := &managedXraySelectorFixture{root: t.TempDir()}
	private := filepath.Join(f.root, "nodes")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	snapshot, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"},
		"vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls", time.Now().Add(-time.Second), time.Hour, false)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("actual node import", err)
	}
	f.node = snapshot.Nodes[0].ID
	f.a = &App{Nodes: nodes, Dataplane: dataplane.New(filepath.Join(f.root, "runtime")), FreshProfile: stableNodeProfile}
	f.adapter, err = NewXrayNodeRuntime(NodeRuntimeFactoryOptions{
		Configs: engineconfig.New(filepath.Join(f.root, "stage"), filepath.Join(f.root, "backup")),
		Nodes:   nodes, StateRoot: f.a.Dataplane.StateRoot, FreshProfile: f.a.FreshProfile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.Dataplane.Register(f.adapter); err != nil {
		t.Fatal(err)
	}
	panel, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	t.Cleanup(cancel)
	f.policy = &managedListPolicyOwner{app: f.a, manager: f.a.Dataplane, panel: panel,
		provider: &netidentity.Provider{}, tools: &startuptools.Lease{}, inventory: &dataplane.BackendInventory{},
		gate: &dataplane.NetworkPolicyAdapter{}, control: &operationgate.ControlEpochReview{}, startupReady: true}
	f.policy.self = f.policy
	f.a.managedListPolicy = f.policy
	f.runtime = &ManagedXraySelectedTCPListRuntime{app: f.a, manager: f.a.Dataplane, policy: f.policy, adapter: f.adapter}
	f.runtime.self = f.runtime
	f.policy.xray = f.runtime
	f.a.managedXraySelectedTCPList = f.runtime
	f.a.NodeHistoryWriteGuard = func(ctx context.Context, required int) error {
		if required != nodestore.XrayHistoryReadVersion {
			return errors.New("wrong history admission version")
		}
		return ctx.Err()
	}
	return f
}

func (f *managedXraySelectorFixture) pass() nodestore.CheckRecord {
	at := time.Now().Add(-time.Millisecond)
	return nodestore.CheckRecord{ProbeID: "selector-proof", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab",
		RoutePathID: "xray:" + f.node, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service",
		CheckedAt: at, ExpiresAt: at.Add(time.Hour)}
}

func (f *managedXraySelectorFixture) record(t *testing.T, record nodestore.CheckRecord) {
	t.Helper()
	if _, err := f.a.Nodes.RecordCheck(context.Background(), f.node, record, record.CheckedAt); err != nil {
		t.Fatal("actual health record", err)
	}
}

func managedXraySelectorBase() []routecatalog.Option {
	return []routecatalog.Option{{ID: "direct", Selectable: true, Ready: true}, {ID: "xray", Installed: true, Running: true}}
}

func TestManagedXrayNodeSelectorOriginalDispatcherSelectableWithoutReady(t *testing.T) {
	f := newManagedXraySelectorFixture(t)
	f.record(t, f.pass())
	group, err := f.a.Nodes.CreateGroup(context.Background(), "Manual", "manual", []string{f.node}, f.node, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	base := managedXraySelectorBase()
	originalBase := append([]routecatalog.Option(nil), base...)
	if f.adapter.NodeTUNProbe != nil {
		t.Fatal("ordinary factory unexpectedly acquired an independent LAN observer")
	}
	verifiedRuntime := f.a.Dataplane.XrayNodeRouteCapable()
	options := f.a.appendNodeRouteOptions(context.Background(), base)
	route := "xray:" + f.node
	if !routecatalog.ValidForServiceWithOptions(route, "telegram", options) || routecatalog.ReadyWithOptions(route, options) != verifiedRuntime {
		t.Fatal("original managed selection lost its independent verifier boundary", options)
	}
	if routecatalog.ValidForServiceWithOptions(route, "youtube", options) || routecatalog.ValidWithOptions("xray:"+group.ID, options) != verifiedRuntime {
		t.Fatal("managed selection widened its service or unsupported group", options)
	}
	expectedAuto := "direct"
	if verifiedRuntime {
		expectedAuto = route
	}
	if plannedEngineWithOptions(catalog.Service{Strategy: []string{route}}, nil, options) != expectedAuto {
		t.Fatal("selector alone granted an AUTO-ready route")
	}
	after, err := f.a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(originalBase, base) {
		t.Fatal("selector changed store or base inventory", err)
	}
	for _, path := range []string{f.a.Dataplane.StateRoot, filepath.Join(f.root, "stage"), filepath.Join(f.root, "backup")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("selector created runtime material", path, err)
		}
	}
	if f.runtime.preparing != nil || f.runtime.active != nil || f.runtime.pending != nil || f.runtime.stopped != nil || f.a.Operations.Snapshot().Active != 0 {
		t.Fatal("selector acquired execution or operation authority")
	}
}

func TestManagedXrayNodeSelectorPreservesLegacyScopedNodeAndGroupReady(t *testing.T) {
	f := newManagedXraySelectorFixture(t)
	f.record(t, f.pass())
	group, err := f.a.Nodes.CreateGroup(context.Background(), "Manual", "manual", []string{f.node}, f.node, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := dataplane.NewScopedXrayTunnelAdapter(f.adapter.Configs, f.a.Dataplane.StateRoot, f.adapter.NodeRoutes)
	if err != nil {
		t.Fatal(err)
	}
	scoped.NodeTUNProbe = func(context.Context, dataplane.NodeTUNRequest) (dataplane.NodeTUNObservation, error) {
		t.Fatal("selector invoked the independent LAN probe")
		return dataplane.NodeTUNObservation{}, errors.New("selector must not probe")
	}
	f.a.Dataplane = dataplane.New(f.a.Dataplane.StateRoot)
	if err := f.a.Dataplane.Register(scoped); err != nil {
		t.Fatal(err)
	}
	f.a.managedXraySelectedTCPList, f.a.managedListPolicy = nil, nil
	options := f.a.appendNodeRouteOptions(context.Background(), managedXraySelectorBase())
	for _, route := range []string{"xray:" + f.node, "xray:" + group.ID} {
		if !routecatalog.ValidForServiceWithOptions(route, "telegram", options) || !routecatalog.ReadyWithOptions(route, options) {
			t.Fatal("legacy scoped node/group semantics changed", route, options)
		}
	}
}

func TestManagedXrayNodeSelectorRefusesUnavailableOwnersAndFactory(t *testing.T) {
	cases := []struct {
		name   string
		change func(*managedXraySelectorFixture)
	}{
		{"no-runtime", func(f *managedXraySelectorFixture) { f.a.managedXraySelectedTCPList = nil }},
		{"copied-runtime", func(f *managedXraySelectorFixture) { f.runtime.self = &ManagedXraySelectedTCPListRuntime{} }},
		{"foreign-app", func(f *managedXraySelectorFixture) { f.runtime.app = &App{} }},
		{"foreign-manager", func(f *managedXraySelectorFixture) { f.runtime.manager = dataplane.New(t.TempDir()) }},
		{"closed-runtime", func(f *managedXraySelectorFixture) { f.runtime.closed = true }},
		{"missing-policy", func(f *managedXraySelectorFixture) { f.runtime.policy = nil }},
		{"foreign-policy-slot", func(f *managedXraySelectorFixture) { f.a.managedListPolicy = &managedListPolicyOwner{} }},
		{"copied-policy", func(f *managedXraySelectorFixture) { f.policy.self = &managedListPolicyOwner{} }},
		{"foreign-policy-app", func(f *managedXraySelectorFixture) { f.policy.app = &App{} }},
		{"foreign-policy-manager", func(f *managedXraySelectorFixture) { f.policy.manager = dataplane.New(t.TempDir()) }},
		{"closed-policy", func(f *managedXraySelectorFixture) { f.policy.closed.Store(true) }},
		{"incomplete-startup", func(f *managedXraySelectorFixture) { f.policy.startupReady = false }},
		{"failed-startup", func(f *managedXraySelectorFixture) { f.policy.startupFailure = errors.New("startup failed") }},
		{"closed-panel", func(f *managedXraySelectorFixture) { f.cancel() }},
		{"missing-provider", func(f *managedXraySelectorFixture) { f.policy.provider = nil }},
		{"missing-tools", func(f *managedXraySelectorFixture) { f.policy.tools = nil }},
		{"missing-inventory", func(f *managedXraySelectorFixture) { f.policy.inventory = nil }},
		{"missing-gate", func(f *managedXraySelectorFixture) { f.policy.gate = nil }},
		{"missing-control", func(f *managedXraySelectorFixture) { f.policy.control = nil }},
		{"detached-runtime", func(f *managedXraySelectorFixture) { f.policy.xray = nil }},
		{"retired-policy-binding", func(f *managedXraySelectorFixture) { f.policy.xrayClosed = true }},
		{"missing-original-adapter", func(f *managedXraySelectorFixture) { f.runtime.adapter = nil }},
		{"missing-dispatcher", func(f *managedXraySelectorFixture) { delete(f.a.Dataplane.Adapters, "xray") }},
		{"missing-materializer", func(f *managedXraySelectorFixture) { f.adapter.NodeRoutes = nil }},
		{"missing-config-owner", func(f *managedXraySelectorFixture) { f.adapter.Configs = nil }},
		{"missing-profile-owner", func(f *managedXraySelectorFixture) { f.adapter.FreshProfile = nil }},
		{"missing-process-owner", func(f *managedXraySelectorFixture) { f.adapter.Processes = nil }},
		{"missing-admission", func(f *managedXraySelectorFixture) { f.a.NodeHistoryWriteGuard = nil }},
		{"refused-admission", func(f *managedXraySelectorFixture) {
			f.a.NodeHistoryWriteGuard = func(context.Context, int) error { return errors.New("refused") }
		}},
		{"changed-dispatcher", func(f *managedXraySelectorFixture) {
			other, err := NewXrayNodeRuntime(NodeRuntimeFactoryOptions{Configs: f.adapter.Configs, Nodes: f.a.Nodes,
				StateRoot: f.a.Dataplane.StateRoot, FreshProfile: f.a.FreshProfile})
			if err != nil {
				t.Fatal(err)
			}
			f.a.Dataplane.Adapters["xray"] = other
		}},
		{"scoped-router-without-dispatcher", func(f *managedXraySelectorFixture) {
			other, err := dataplane.NewScopedXrayRouterTunnelAdapter(f.adapter.Configs, f.a.Dataplane.StateRoot, f.adapter.NodeRoutes)
			if err != nil {
				t.Fatal(err)
			}
			other.FreshProfile = f.a.FreshProfile
			f.runtime.adapter = other
			f.a.Dataplane.Adapters["xray"] = other
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newManagedXraySelectorFixture(t)
			f.record(t, f.pass())
			test.change(f)
			if test.name != "missing-admission" && test.name != "refused-admission" && f.a.managedXrayNodeSelectionCapable(context.Background()) {
				t.Fatal("unavailable owner or factory permitted managed selection")
			}
			// An independent router verifier is a separate authority path on
			// supported hosts; losing managed-list ownership cannot revoke it.
			want := f.a.Dataplane.XrayNodeRouteCapable() && f.a.nodeHistoryAdmission(context.Background(), "xray") == nil
			if routecatalog.ValidWithOptions("xray:"+f.node, f.a.appendNodeRouteOptions(context.Background(), managedXraySelectorBase())) != want {
				t.Fatal("selector confused managed ownership with independent node verification")
			}
		})
	}
}

func TestManagedXrayNodeSelectorKeepsExactFreshHealthAndInstallation(t *testing.T) {
	cases := []string{"absent", "foreign-engine", "foreign-service", "foreign-wan", "expired", "future", "protocol-only", "direct-leak", "latest-error", "disabled", "uninstalled", "wan-error", "changed-wan", "canceled", "expired-context"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newManagedXraySelectorFixture(t)
			record := f.pass()
			base, ctx := managedXraySelectorBase(), context.Background()
			switch name {
			case "foreign-engine":
				record.RoutePathID = "sing-box:" + f.node
			case "foreign-service":
				record.ServiceID = "youtube"
			case "foreign-wan":
				record.NetworkProfile = "wan-ffffffffffff"
			case "expired":
				record.CheckedAt, record.ExpiresAt = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			case "future":
				record.CheckedAt, record.ExpiresAt = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
			case "protocol-only":
				record.TestLevel = "protocol"
			case "direct-leak":
				record.DirectLeak = true
			case "uninstalled":
				base[1].Installed = false
			case "wan-error":
				f.a.FreshProfile = func(context.Context) (string, error) { return "", errors.New("no fresh WAN") }
			case "changed-wan":
				f.a.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			if name != "absent" {
				f.record(t, record)
			}
			if name == "disabled" {
				if _, err := f.a.Nodes.SetDisabled(context.Background(), f.node, true, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if name == "latest-error" {
				record.ProbeID, record.Verdict, record.State, record.TestLevel, record.Stage = "latest-error", "ERROR", "unavailable", "transport", "transport"
				f.record(t, record)
			}
			options := f.a.appendNodeRouteOptions(ctx, base)
			if routecatalog.ValidForServiceWithOptions("xray:"+f.node, "telegram", options) {
				t.Fatal("missing exact current service health or inventory permitted selection", options)
			}
		})
	}
}
