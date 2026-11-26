package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNFQWSScopedInventoryAllRegisteredRowsAndForeignCapture(t *testing.T) {
	plan, spec := nfqwsScopedTypedSpec(t, netidentity.ReviewedSingleInitNet)
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := BackendInventorySnapshot{Schema: 1, Scope: backendInventoryScope{Network: *spec.NetworkIdentity, ToolReviewID: strings.Repeat("a", 64)},
		Coverage: BackendInventoryCoverage{LegacyRegisteredBothFamilies: true, RegisteredTablesComplete: true, NativeNFTAllFamilies: true},
		NFTState: BackendNFTNoRegisteredSubsystemAtCapture,
		Rows:     []BackendInventoryRow{{Family: 4, Table: "vendor_extra", Tokens: []string{"-A", "FORWARD", "-m", "comment", "--comment", "literal -j NFQUEUE", "-j", "ACCEPT"}}}}
	rules, err := nfqwsScopedInventoryRules(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ruleCounts(rules, nfqwsScopedBeforeStart); err != nil {
		t.Fatal("opaque comment became executable capture", err)
	}
	snapshot.Rows[0].Tokens[1] = "CHANGED"
	if rules[PolicyEffectIPTables]["vendor_extra"][0][1] != "FORWARD" {
		t.Fatal("collector snapshot aliases ownership predicates")
	}
	snapshot.Rows = append(snapshot.Rows, BackendInventoryRow{Family: 6, Table: "vendor_extra", Tokens: []string{"-A", "FORWARD", "-j", "NFQUEUE", "--queue-num", "99"}})
	rules, err = nfqwsScopedInventoryRules(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ruleCounts(rules, nfqwsScopedBeforeStart); err == nil {
		t.Fatal("foreign IPv6 capture outside fixed tables was discarded")
	}
	for _, change := range []func(*BackendInventorySnapshot){
		func(s *BackendInventorySnapshot) { s.NFTState = BackendNFTUnknown },
		func(s *BackendInventorySnapshot) { s.Coverage.RegisteredTablesComplete = false },
		func(s *BackendInventorySnapshot) {
			s.NFTState = BackendNFTPresent
			s.NFTTables = []BackendNFTTable{{Family: 7, Name: "foreign"}}
		},
		func(s *BackendInventorySnapshot) {
			s.Rows = []BackendInventoryRow{{Family: 7, Table: "filter", Tokens: []string{"-P", "FORWARD", "ACCEPT"}}}
		},
	} {
		copy := snapshot
		change(&copy)
		if _, err := nfqwsScopedInventoryRules(copy); err == nil {
			t.Fatal("unknown/incomplete/foreign inventory passed owner reader")
		}
	}
}

func TestNFQWSScopedTypedBindingRequiresConcreteProviderAndNeverFallsBack(t *testing.T) {
	b, _, _ := nfqwsScopedBindingFixture(t)
	provider := &netidentity.Provider{}
	toolCalls, legacyCalls := 0, 0
	runner := backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) {
		toolCalls++
		return []byte("-P FORWARD ACCEPT\n"), nil
	})
	b.Runner = runner
	root := t.TempDir()
	iptables, ip6tables := filepath.Join(root, "iptables"), filepath.Join(root, "ip6tables")
	b.Tools.IPTables, b.Tools.IP6Tables = iptables, ip6tables
	b.QueueCheck = func(context.Context, string, uint16, *components.NFQWSRuntimeProcessIdentity) error {
		legacyCalls++
		return nil
	}
	inventory, err := NewReviewedStockNC1812BackendInventory(provider, BackendInventoryTools{Runner: runner, IPTables: b.Tools.IPTables, IP6Tables: b.Tools.IP6Tables,
		ReviewSHA256: strings.Repeat("a", 64), Check: func(context.Context, netidentity.Identity) error { toolCalls++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := NewTypedNFQWSScopedBinding(provider, inventory, *b)
	if err != nil || bound.QueueCheck != nil {
		t.Fatal("typed construction retained a legacy queue callback", err)
	}
	inventory.review = strings.Repeat("b", 64)
	inventory.reader.IPTables = "/altered"
	inventory.reader.CheckTools = nil
	b.Tools.IPTables = "/altered"
	if bound.network.inventory.review != strings.Repeat("a", 64) || bound.network.inventory.reader.IPTables != iptables || bound.network.inventory.reader.CheckTools == nil || bound.Tools.IPTables != iptables {
		t.Fatal("caller mutation changed held binding")
	}
	plan, spec := nfqwsScopedTypedSpec(t, netidentity.ReviewedSingleInitNet)
	p, _ := CompileNFQWSScopedPlan(plan, spec)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if bound.checkQueue(ctx, p, nil) == nil {
		t.Fatal("zero provider became whole queue absence")
	}
	if ready, err := bound.checkQueueReadiness(ctx, p, &components.NFQWSRuntimeProcessIdentity{PID: 3000, BootID: spec.BootID}); err == nil || ready {
		t.Fatal("zero provider became ready queue")
	}
	if _, err := bound.readClassicRules(ctx, p); err == nil {
		t.Fatal("zero provider became complete registered inventory")
	}
	if _, err := bound.readTargetRules(ctx, p, PolicyEffectIPTables); err == nil {
		t.Fatal("zero provider granted unscoped actual CLI")
	}
	if toolCalls != 0 || legacyCalls != 0 {
		t.Fatal("typed refusal fell back to tools or legacy namespace callback")
	}
	_, _, legacyPlan := nfqwsScopedFixture(t)
	if _, _, err := bound.prepare(legacyPlan, false); !errors.Is(err, ErrNFQWSScopedOwner) {
		t.Fatal("typed binding accepted untyped persisted spec")
	}
	if _, _, err := b.prepare(p, false); !errors.Is(err, ErrNFQWSScopedOwner) {
		t.Fatal("legacy binding accepted typed metadata without concrete reader")
	}
}

func TestNFQWSScopedTypedBindingKeepsDistinctOriginalEffectAndBoundedReadRunners(t *testing.T) {
	b, _, _ := nfqwsScopedBindingFixture(t)
	provider := &netidentity.Provider{}
	readCalls, effectCalls := 0, 0
	read := backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) { readCalls++; return nil, nil })
	effect := nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) { effectCalls++; return nil, nil })
	b.Runner = effect // The actual policy runner intentionally has no bounded read ABI.
	root := t.TempDir()
	b.Tools.IPTables, b.Tools.IP6Tables = filepath.Join(root, "iptables"), filepath.Join(root, "ip6tables")
	inventory, err := NewReviewedStockNC1812BackendInventory(provider, BackendInventoryTools{Runner: read, IPTables: b.Tools.IPTables, IP6Tables: b.Tools.IP6Tables,
		ReviewSHA256: strings.Repeat("a", 64), Check: func(context.Context, netidentity.Identity) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := NewTypedNFQWSScopedBinding(provider, inventory, *b)
	if err != nil || bound == nil {
		t.Fatal("effect-only producer refused despite original bounded inventory", err)
	}
	if _, ok := bound.Runner.(backendInventoryBoundedRunner); ok {
		t.Fatal("fixture effect producer accidentally acquired a read ABI")
	}
	if _, ok := bound.network.inventory.reader.Runner.(backendInventoryBoundedRunner); !ok {
		t.Fatal("bounded read producer was lost")
	}
	inventory.reader.Runner = effect
	if _, err := NewTypedNFQWSScopedBinding(provider, inventory, *b); err == nil {
		t.Fatal("unbounded inventory was repaired using an effect runner")
	}
	if _, err := bound.Runner.Run(context.Background(), bound.Tools.IPTables, "model-effect"); err != nil || effectCalls != 1 || readCalls != 0 {
		t.Fatal("effect did not retain its original producer", err, effectCalls, readCalls)
	}
}

func TestNFQWSScopedTypedBindingRejectsForeignToolOrProviderPair(t *testing.T) {
	b, _, _ := nfqwsScopedBindingFixture(t)
	provider := netidentity.NewProcProvider()
	runner := backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	b.Runner = runner
	root := t.TempDir()
	b.Tools.IPTables, b.Tools.IP6Tables = filepath.Join(root, "iptables"), filepath.Join(root, "ip6tables")
	inventory, err := NewBackendInventory(provider, BackendInventoryTools{Runner: runner, IPTables: b.Tools.IPTables, IP6Tables: b.Tools.IP6Tables,
		ReviewSHA256: strings.Repeat("a", 64), Check: func(context.Context, netidentity.Identity) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*BackendInventory, *NFQWSScopedBinding){
		func(r *BackendInventory, _ *NFQWSScopedBinding) { r.reader.Provider = netidentity.NewProcProvider() },
		func(_ *BackendInventory, b *NFQWSScopedBinding) { b.Tools.IP6Tables = "/foreign" },
		func(_ *BackendInventory, b *NFQWSScopedBinding) { b.AdditionalReadback = nil },
		func(r *BackendInventory, _ *NFQWSScopedBinding) { r.reader.CheckTools = nil },
	} {
		copy, binding := *inventory, *b
		change(&copy, &binding)
		if got, err := NewTypedNFQWSScopedBinding(provider, &copy, binding); err == nil || got != nil {
			t.Fatal("foreign/incomplete concrete pair became typed binding")
		}
	}
}
