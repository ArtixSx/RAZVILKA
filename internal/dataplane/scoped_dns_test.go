package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

type dnsFirewallFixture struct {
	rules             [][]string
	chains            map[string][][]string
	addCount, failAdd int
}

func (f *dnsFirewallFixture) Run(ctx context.Context, _ string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.chains == nil {
		f.chains = map[string][][]string{}
	}
	if len(args) < 3 || args[0] != "-t" || args[1] != "nat" {
		return nil, errors.New("unexpected firewall command")
	}
	if args[2] == "-S" {
		var lines []string
		for _, r := range f.rules {
			lines = append(lines, "-A PREROUTING "+strings.Join(r, " "))
		}
		for chain, rules := range f.chains {
			lines = append(lines, "-N "+chain)
			for _, r := range rules {
				lines = append(lines, "-A "+chain+" "+strings.Join(r, " "))
			}
		}
		return []byte(strings.Join(lines, "\n")), nil
	}
	chain := args[3]
	rules := f.chains[chain]
	if chain == "PREROUTING" {
		rules = f.rules
	}
	index := -1
	for i, r := range rules {
		if reflect.DeepEqual(r, args[4:]) {
			index = i
			break
		}
	}
	switch args[2] {
	case "-N":
		if _, exists := f.chains[chain]; exists {
			return nil, errors.New("exists")
		}
		f.chains[chain] = [][]string{}
		return nil, nil
	case "-X":
		if len(rules) != 0 {
			return nil, errors.New("not empty")
		}
		delete(f.chains, chain)
		return nil, nil
	case "-C":
		if index < 0 {
			return nil, errors.New("missing")
		}
	case "-I", "-A":
		if args[2] == "-I" {
			f.addCount++
		}
		if args[2] == "-I" && f.addCount == f.failAdd {
			return nil, errors.New("injected add failure")
		}
		rules = append(rules, append([]string(nil), args[4:]...))
	case "-D":
		if index < 0 {
			return nil, errors.New("missing")
		}
		rules = append(rules[:index], rules[index+1:]...)
	default:
		return nil, errors.New("unexpected firewall mutation")
	}
	if chain == "PREROUTING" {
		f.rules = rules
	} else {
		f.chains[chain] = rules
	}
	return nil, nil
}

func scopedAdapterFixture(t *testing.T) (*Manager, *ScopedDNSAdapter, *dnsFirewallFixture, Input) {
	t.Helper()
	dns, err := dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	id, err := dns.ScopedProfileIdentity("private")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	life, cancel := context.WithCancel(context.Background())
	a := NewScopedDNSAdapter(life, dns, root)
	a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	a.ScopeCheck = func(ctx context.Context, _ ScopedDNSPlan) error { return ctx.Err() }
	a.HealthProbe = func(ctx context.Context, _ *dnscontrol.ScopedDNSResolver, _ Plan) error { return ctx.Err() }
	a.listen = func(netip.AddrPort) (*net.UDPConn, *net.TCPListener, error) {
		return listenScopedDNS(netip.MustParseAddrPort("127.0.0.1:0"))
	}
	f := &dnsFirewallFixture{}
	a.Runner = f
	m := New(filepath.Join(root, "journal"))
	m.FreshProfile = a.FreshProfile
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Deactivate(context.Background()); cancel() })
	in := Input{Revision: 1, NetworkProfileID: executionNetwork, DNS: &ScopedDNSPlan{Listener: "192.168.1.1:10553", Ingress: "br0", Bindings: []ScopedDNSBinding{{ServiceID: "web", Client: "192.168.1.40", Domain: "example.com", ProfileID: "private", ProfileDigest: id}}}, Routes: []Route{{ServiceID: "web", ServiceName: "Example", Resolved: "direct", Selected: "direct", Sources: []string{"192.168.1.40/32"}, Domains: []string{"example.com"}, ProbeURL: "https://example.com/"}}}
	in.Engines = []Engine{{ID: a.ID(), Installed: true, Configured: true, Activatable: true}}
	in.DNS.Probe = catalog.Probe{ID: "web", Label: "Web", URL: in.Routes[0].ProbeURL, Required: true}
	return m, a, f, in
}

func TestScopedDNSTransactionCommitsAndRemovesOnlyOwnedRules(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	f.rules = append(f.rules, []string{"-s", "192.168.1.99/32", "-j", "RETURN"})
	p, err := Build(in)
	if err != nil || !p.Ready || p.Noop || !p.RequiresNetworkProof() {
		t.Fatalf("invalid DNS plan: %+v %v", p, err)
	}
	committed := false
	e, err := m.Apply(context.Background(), p, func() (func() error, error) {
		committed = true
		return func() error { committed = false; return nil }, nil
	})
	if err != nil || e.State != "committed" || !committed || len(f.rules) != 3 {
		t.Fatalf("apply: %+v %v", e, err)
	}
	if saved, _, _ := m.Committed(); saved.RouteEvidence[0].Observed != "none" {
		t.Fatal("DNS process success was promoted to client proof")
	}
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 1 || a.live != nil {
		t.Fatal("cleanup changed unrelated state or leaked worker")
	}
	if _, err := os.Stat(a.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ownership record remained")
	}
}

func TestScopedDNSTransactionPartialActivationAndCommitFailureRollBack(t *testing.T) {
	for _, phase := range []string{"second-rule", "health", "commit"} {
		t.Run(phase, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			if phase == "second-rule" {
				f.failAdd = 2
			}
			if phase == "health" {
				a.HealthProbe = func(context.Context, *dnscontrol.ScopedDNSResolver, Plan) error { return errors.New("probe failed") }
			}
			p, _ := Build(in)
			e, err := m.Apply(context.Background(), p, func() (func() error, error) {
				if phase == "commit" {
					return nil, errors.New("settings disk failed")
				}
				return nil, nil
			})
			if err == nil || e.State != "rolled-back" || !e.RollbackVerified || len(f.rules) != 0 || a.live != nil {
				t.Fatalf("rollback: %+v err=%v rules=%d live=%v", e, err, len(f.rules), a.live != nil)
			}
			if _, exists, _ := m.Committed(); exists {
				t.Fatal("failed DNS candidate published")
			}
		})
	}
}

func TestScopedDNSReplacementRestoresPreviousPolicy(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	before := a.live.state
	in.Revision++
	in.DNS.Bindings[0].ProfileID = "unfiltered"
	id, err := a.DNS.ScopedProfileIdentity("unfiltered")
	if err != nil {
		t.Fatal(err)
	}
	in.DNS.Bindings[0].ProfileDigest = id
	next, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	a.HealthProbe = func(context.Context, *dnscontrol.ScopedDNSResolver, Plan) error {
		return errors.New("new canary failed")
	}
	e, err := m.Apply(context.Background(), next, nil)
	if err == nil || !e.RollbackVerified || e.State != "rolled-back" || len(f.rules) != 2 || !dnsSessionAlive(a.live) || !reflect.DeepEqual(before, a.live.state) {
		t.Fatalf("previous policy not restored: %+v %v", e, err)
	}
	if saved, _, _ := m.Committed(); saved.Digest != p.Digest {
		t.Fatal("previous commit lost")
	}
}

func TestScopedDNSPlanRejectsScopeExpansionAndBindsDigest(t *testing.T) {
	_, _, _, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	in.DNS.Bindings[0].ProfileDigest = strings.Repeat("b", 64)
	next, _ := Build(in)
	if p.Digest == next.Digest {
		t.Fatal("DNS provider not in route digest")
	}
	in.DNS.Bindings[0].Client = "192.168.1.41"
	if _, err := Build(in); err == nil {
		t.Fatal("expanded client scope accepted")
	}
	in.DNS.Bindings[0].Client = "192.168.1.40"
	in.Routes[0].Resolved = "usque"
	if _, err := Build(in); err == nil {
		t.Fatal("unimplemented DNS+VPN combination accepted")
	}
}

func TestScopedDNSForeignRuleBlocksCleanup(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	original := append([]string(nil), f.rules[0]...)
	f.rules[0][1] = "192.168.1.99/32"
	if err := a.Deactivate(context.Background()); err == nil {
		t.Fatal("changed rule was treated as owned")
	}
	if len(f.rules) != 2 || !dnsSessionAlive(a.live) {
		t.Fatal("partial cleanup despite conflicting owner")
	}
	f.rules[0] = original
}

func TestScopedDNSRetirementAndMixedRouteRollback(t *testing.T) {
	for _, mode := range []string{"retire", "other-route-fails", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if mode == "retire" {
				if _, err := m.Apply(context.Background(), p, nil); err != nil {
					t.Fatal(err)
				}
				in.Revision++
				in.DNS = nil
				in.RetiringAdapters = []string{scopedDNSAdapterID}
				retire, err := Build(in)
				if err != nil || retire.Noop || !retire.Ready {
					t.Fatal("retirement lost", retire, err)
				}
				e, err := m.Apply(context.Background(), retire, nil)
				if err != nil || e.State != "committed" || a.live != nil || len(f.rules) != 0 || len(f.chains) != 0 {
					t.Fatal("retirement failed", e, err)
				}
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				a.HealthProbe = func(context.Context, *dnscontrol.ScopedDNSResolver, Plan) error { cancel(); return context.Canceled }
			} else {
				base := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "xray"}, after: func(phase string) error {
					if phase == "health" {
						return errors.New("other route failed")
					}
					return nil
				}}
				sibling := &rollbackVerifierFake{networkExecutionAdapter: base, verify: func(context.Context) (bool, error) { return base.rollback, nil }}
				if err := m.Register(sibling); err != nil {
					t.Fatal(err)
				}
				p.Adapters = append(p.Adapters, "xray")
			}
			e, err := m.Apply(ctx, p, nil)
			if err == nil || e.State != "rolled-back" || !e.RollbackVerified || a.live != nil || len(f.rules) != 0 || len(f.chains) != 0 {
				t.Fatalf("joint rollback failed: %+v %v", e, err)
			}
		})
	}
}

func TestScopedDNSGuardsDoNotMutateOnScopeOrProviderMismatch(t *testing.T) {
	for _, mode := range []string{"scope", "provider", "epoch"} {
		t.Run(mode, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			switch mode {
			case "scope":
				a.ScopeCheck = func(context.Context, ScopedDNSPlan) error { return errors.New("client moved") }
			case "provider":
				in.DNS.Bindings[0].ProfileDigest = strings.Repeat("b", 64)
			case "epoch":
				a.FreshProfile = func(context.Context) (string, error) { return "wan-abcdef012345", nil }
				m.FreshProfile = a.FreshProfile
			}
			p, _ := Build(in)
			e, err := m.Apply(context.Background(), p, nil)
			if err == nil || e.State == "committed" || len(f.rules) != 0 || len(f.chains) != 0 || a.live != nil {
				t.Fatal("invalid authority touched DNS", e, err)
			}
		})
	}
}

func TestScopedDNSForeignChainContentsAndReferencesAreNotDeleted(t *testing.T) {
	for _, mode := range []string{"contents", "foreign-reference", "duplicate-reference"} {
		t.Run(mode, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			chain := a.rules(p.DNS)[0].chain
			if mode == "contents" {
				f.chains[chain] = append(f.chains[chain], []string{"-j", "RETURN"})
			} else {
				ref := append([]string(nil), f.rules[0]...)
				if mode == "foreign-reference" {
					ref[1] = "192.168.1.99/32"
				}
				f.rules = append(f.rules, ref)
			}
			if err := a.Deactivate(context.Background()); err == nil {
				t.Fatal("conflicting ownership accepted")
			}
			if !dnsSessionAlive(a.live) {
				t.Fatal("listener closed while redirects remain")
			}
			if mode == "contents" {
				f.chains[chain] = f.chains[chain][:1]
			} else {
				f.rules = f.rules[:2]
			}
		})
	}
}

func TestScopedDNSCannotBeOrphanedByARouteOnlyApply(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	in.Revision++
	in.DNS = nil
	next, _ := Build(in)
	if _, err := m.Apply(context.Background(), next, nil); err == nil {
		t.Fatal("route-only plan orphaned DNS")
	}
	if !dnsSessionAlive(a.live) || len(f.rules) != 2 || len(f.chains) != 2 {
		t.Fatal("refusal changed working DNS")
	}
	if saved, _, _ := m.Committed(); saved.Digest != p.Digest {
		t.Fatal("working plan changed")
	}
}

func TestScopedDNSCommittedReadbackAndSameEpochRecovery(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	saved, _, _ := m.Committed()
	calls := 0
	a.HealthProbe = func(context.Context, *dnscontrol.ScopedDNSResolver, Plan) error { calls++; return nil }
	if err := m.ObserveCommittedRuntime(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("runtime observation made external probe")
	}
	// Simulate only the local listener disappearing. The durable owner and
	// kernel rules remain; recovery must not derive authority from the port.
	a.live.cancel()
	<-a.live.done
	a.live = nil
	if err := m.ObserveCommittedRuntime(context.Background(), saved); err == nil {
		t.Fatal("dead listener reported active")
	}
	r, err := m.Recover(context.Background())
	if err != nil || r.State != "recovered" || calls != 1 || !dnsSessionAlive(a.live) || len(f.rules) != 2 {
		t.Fatal("exact recovery failed", r, err)
	}
	if err := m.ObserveCommittedRuntime(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
}

func TestScopedDNSBuildRequiresRegisteredCapabilityAndNetwork(t *testing.T) {
	_, _, _, in := scopedAdapterFixture(t)
	in.Engines = nil
	if p, err := Build(in); err != nil || p.Ready || p.Noop {
		t.Fatal("missing capability is ready", p, err)
	}
	in.NetworkProfileID = ""
	if p, err := Build(in); err != nil || p.Ready {
		t.Fatal("unknown network is ready", p, err)
	}
}

func TestScopedDNSPlanFreezesScenarioSemantics(t *testing.T) {
	_, _, _, in := scopedAdapterFixture(t)
	in.DNS.Probe.Expect.BodyContains = []string{"expected account page"}
	p, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	in.DNS.Probe.Expect.BodyContains[0] = "different page"
	next, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest == next.Digest || p.DNS.Probe.Expect.BodyContains[0] != "expected account page" {
		t.Fatal("scenario changed behind immutable DNS plan")
	}
	in.DNS.Probe.URL = "http://example.com/"
	in.Routes[0].ProbeURL = in.DNS.Probe.URL
	if _, err := Build(in); err == nil {
		t.Fatal("plaintext canary accepted")
	}
}
