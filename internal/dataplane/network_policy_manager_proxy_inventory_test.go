package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Explicit kernel/process model. Actual owner compilers, mixed LAN receipt,
// proxy forwarding lease, schema-1 addition receipt and live owner validators
// run unchanged. The pending Stage generation producer fix is not emulated by
// a production verifier waiver: this fixture explicitly prepares typed intent.
func networkPolicyScopedProxyInventoryFixture(t *testing.T) (*NetworkPolicyChecks, context.Context, Plan, *scopedXrayFixture, string, PolicyState) {
	t.Helper()
	m, _, gate, oldChecks, _, model, _ := networkPolicyChecksTestFixture(t)
	f := scopedXrayTestFixture(t)
	baseRunner := f.a.Runner
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// The existing LAN FIB probe double treats any iif-br0 argv as a
		// lookup. Managed RPDB mutations must reach its actual stateful model.
		if name == "ip" && slices.Contains(args, "rule") {
			return f.runner.Run(ctx, name, args...)
		}
		return baseRunner.Run(ctx, name, args...)
	})
	f.a.bootIdentity = func() (string, error) { return gate.identity.value.BootID, nil }
	route := f.plan.Routes[0]
	route.Domains, route.CIDRs = nil, []string{"8.8.8.8/32"}
	route.Ingress, route.NetworkPolicyGeneration, route.NetworkPolicyRole = []string{"br0"}, model.plan.Generation, "override"
	p, err := BuildAt(Input{LAN: model.plan, NetworkProfileID: executionNetwork, Revision: 1, Routes: []Route{route},
		Engines: []Engine{{ID: NetworkPolicyAdapterID, Installed: true, Configured: true, Activatable: true}, {ID: "xray", Installed: true, Configured: true, Activatable: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true, TUN: true, SingBox: true}}, time.Unix(100, 0))
	if err != nil || !p.Ready {
		t.Fatal("typed proxy plan", err, p.Blockers)
	}
	// Empty omitempty slices normalize to nil when the existing manifest is
	// read back. Keep this explicit fixture in that canonical representation.
	for i := range p.Routes {
		if len(p.Routes[i].Domains) == 0 {
			p.Routes[i].Domains = nil
		}
		if len(p.Routes[i].SourceRefs) == 0 {
			p.Routes[i].SourceRefs = nil
		}
	}
	f.plan = p
	if err := m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	oldChecks.Close()
	checks, err := m.bindNetworkPolicyChecks(gate, func(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
		var rows []BackendInventoryRow
		for _, family := range []int{4, 6} {
			tool := "iptables"
			if family == 6 {
				tool = "ip6tables"
			}
			for _, table := range []string{"mangle", "filter", "nat"} {
				var data []byte
				var err error
				if table == "mangle" {
					data, err = model.Run(ctx, tool, "-t", table, "-S")
				} else {
					data, err = f.a.Runner.Run(ctx, tool, "-t", table, "-S")
				}
				if err != nil {
					return BackendInventorySnapshot{}, err
				}
				for _, line := range strings.Split(string(data), "\n") {
					if line == "" {
						continue
					}
					tokens, err := backendXTablesRowTokens(line)
					if err != nil {
						return BackendInventorySnapshot{}, err
					}
					rows = append(rows, BackendInventoryRow{Family: family, Table: table, Tokens: tokens})
				}
			}
		}
		// The older firewall model iterates a Go map of chains. Canonicalize
		// only that model's chain enumeration; preserve order WITHIN each chain.
		slices.SortStableFunc(rows, func(a, b BackendInventoryRow) int {
			if a.Family != b.Family {
				return a.Family - b.Family
			}
			if order := strings.Compare(a.Table, b.Table); order != 0 {
				return order
			}
			return strings.Compare(a.Tokens[1], b.Tokens[1])
		})
		return networkPolicyInventoryTestImage(identity, rows), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { checks.Close() })
	// The actual typed wrapper's owner callbacks are rebound only in this model;
	// production builds them once from its same Manager startup construction.
	gate.Binding.Runtime.ScopeCheck = func(ctx context.Context, lan *LANPolicyRuntimePlan) error {
		return checks.InventoryCheck(ctx, checks.network, lan)
	}
	gate.Binding.Runtime.ConsumerCheck = checks.ConsumerCheck
	gate.Binding.ApplyGuard = func(ctx context.Context, lan *LANPolicyRuntimePlan, _ LANPolicyEffect) error {
		return checks.InventoryCheck(ctx, checks.network, lan)
	}
	gate.Binding.CleanupGuard = gate.Binding.ApplyGuard
	gate.Binding.RetireCheck = checks.RetireCheck
	ctx := networkPolicyConsumerContext(context.Background(), p)
	gateRoot := filepath.Join(m.StateRoot, "transactions", p.PlanID, NetworkPolicyAdapterID)
	if err := os.MkdirAll(gateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := gate.Activate(ctx, p, gateRoot); err != nil {
		t.Fatal("actual gate activation", err)
	}
	root := filepath.Join(m.StateRoot, "transactions", p.PlanID, "xray")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	config, hosts, manifest, err := f.a.stageScopedXray(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := f.a.buildEngineCandidate(config, f.a.SOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	side, err := f.a.buildSidecarConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ConfigHash, manifest.SidecarHash = routeidentity.Hash(candidate), routeidentity.Hash(side)
	manifestData, _ := json.Marshal(manifest)
	if err := os.MkdirAll(f.a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		data []byte
	}{{f.a.engineConfigPath(), candidate}, {f.a.sidecarConfigPath(), side}, {f.a.nodeManifestPath(), manifestData}} {
		if err := writeAtomic(item.path, item.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	prefixes, rules, err := resolvePolicyRules(ctx, p, "xray", nil)
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := resolveEndpointExclusions(ctx, hosts, f.a.Resolver)
	if err != nil {
		t.Fatal(err)
	}
	state := PolicyState{Interface: f.a.Interface, Table: f.a.Table, PriorityBase: f.a.Priority, Prefixes: prefixes, Rules: rules, Exclusions: exclusions, NetworkPolicyGeneration: p.LAN.Generation}
	initializePolicyLayout(&state)
	if err := f.a.prepareForwarding(ctx, &state); err != nil {
		t.Fatal(err)
	}
	stateData, _ := json.Marshal(state)
	if err := writeAtomic(filepath.Join(root, "policy.staged.json"), stateData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.a.prepareCandidatePolicy(root, state); err != nil {
		t.Fatal(err)
	}
	if err := f.a.beginCandidatePolicy(root, state); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []ProcessSpec{f.a.engineProcess(), f.a.sidecarProcess()} {
		if err := f.a.Processes.Start(ctx, spec); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.recordScopedNodeInterface(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.a.applyCandidatePolicy(ctx, state, root); err != nil {
		t.Fatal(err)
	}
	return checks, ctx, p, f, root, state
}

func TestNetworkPolicyChecksActualScopedProxyReceiptsAndWholeRows(t *testing.T) {
	checks, ctx, p, f, root, state := networkPolicyScopedProxyInventoryFixture(t)
	if err := checks.ConsumerCheck(ctx, p.LAN); err != nil {
		t.Fatal("real owner/receipt bridge refused exact candidate", err)
	}
	if err := checks.gate.Health(ctx, p, filepath.Join(checks.root, "transactions", p.PlanID, NetworkPolicyAdapterID)); err != nil {
		t.Fatal("LAN readback did not consume exact proxy proof", err)
	}
	if err := f.a.promoteCandidatePolicy(ctx, state, root); err != nil {
		t.Fatal(err)
	}
	if err := f.a.savePolicyJournal(state, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "policy-additions.json")); err != nil {
		t.Fatal(err)
	}
	if err := checks.ConsumerCheck(ctx, p.LAN); err != nil {
		t.Fatal("retained receipt bridge depended on candidate reference", err)
	}
	if err := checks.RetireCheck(ctx, p.LAN); err == nil {
		t.Fatal("active proxy became independently inactive")
	}
}

func TestNetworkPolicyChecksScopedProxyUnknownProofRefusesWithoutEffects(t *testing.T) {
	for _, fault := range []string{"receipt", "lock", "generation", "process", "extra-row", "lost-row", "foreign-table"} {
		t.Run(fault, func(t *testing.T) {
			checks, ctx, p, f, root, _ := networkPolicyScopedProxyInventoryFixture(t)
			originalRead := checks.read
			switch fault {
			case "receipt":
				if err := os.Remove(filepath.Join(root, policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Remove(filepath.Join(root, policyAdditionLock)); err != nil {
					t.Fatal(err)
				}
			case "generation":
				p.LAN = CloneLANPolicyRuntime(p.LAN)
				p.LAN.Generation = strings.Repeat("f", 64)
			case "process":
				delete(f.processes.running, "xray-tun")
			default:
				checks.read = func(c context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
					image, err := originalRead(c, identity)
					if err != nil {
						return image, err
					}
					for i, row := range image.Rows {
						if row.Tokens[0] == "-A" && strings.HasPrefix(row.Tokens[1], "RZP_") {
							switch fault {
							case "extra-row":
								image.Rows = append(image.Rows, row)
							case "lost-row":
								image.Rows = slices.Delete(image.Rows, i, i+1)
							case "foreign-table":
								image.Rows[i].Table = "custom"
							}
							break
						}
					}
					return image, nil
				}
			}
			var calls []string
			base := f.a.Runner
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				return base.Run(ctx, name, args...)
			})
			if err := checks.ConsumerCheck(ctx, p.LAN); err == nil {
				t.Fatal("unknown/changed proof granted consumer allowance", fault)
			}
			if mutated := receiptMutationCalls(calls); len(mutated) != 0 {
				t.Fatal("read-only refusal mutated owner state", mutated)
			}
			if fault == "lock" {
				if _, err := os.Stat(filepath.Join(root, policyAdditionLock)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("observer recreated absent receipt lock", err)
				}
			}
		})
	}
}
