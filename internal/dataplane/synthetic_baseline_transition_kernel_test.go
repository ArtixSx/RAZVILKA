package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// All tests in this file are socket-free comparison models. They issue no
// native reader, process, Manager registration or publication capability.
func syntheticBaselineKernelModel(t *testing.T) (PolicyEffectPlan, []backendInventoryRow) {
	t.Helper()
	plan, err := syntheticBaselineTransitionEffects(dnscontrol.SyntheticDNSMappingObservation{
		Authority:     dnscontrol.NetworkPolicyDNSAuthority{Generation: strings.Repeat("a", 64)},
		PublicationID: strings.Repeat("b", 32), Client: netip.MustParseAddr("192.168.1.42"),
		DeviceID: "selected", MAC: "02:00:00:00:00:02", Ingress: "br0", QName: "service.example.com",
		Synthetic: netip.MustParseAddr("198.18.0.1"), RealIPv4: netip.MustParseAddr("93.184.215.14"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var rows []backendInventoryRow
	for _, table := range []string{"raw", "mangle", "nat"} {
		rows = append(rows, backendInventoryRow{Family: 4, Table: table, Tokens: []string{"-P", "PREROUTING", "ACCEPT"}})
	}
	for _, effect := range plan.Effects {
		rows = append(rows, backendInventoryRow{Family: 4, Table: "nat", Tokens: slices.Clone(effect.Add[2:])})
	}
	return plan, rows
}

func TestSyntheticBaselineKernelExactWholeOwner(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	for i := range plan.Effects {
		count, err := syntheticBaselineExactPresence(rows, plan, i)
		if err != nil || count != 1 {
			t.Fatalf("exact effect %d: %d %v", i, count, err)
		}
	}
	if count, err := syntheticBaselineExactPresence(rows[:3], plan, 2); err != nil || count != 0 {
		t.Fatal("absent owner cannot prepare", count, err)
	}
	chain := plan.Effects[0].Add[3]
	for _, row := range []backendInventoryRow{
		{Family: 6, Table: "nat", Tokens: []string{"-N", chain}},
		{Family: 4, Table: "mangle", Tokens: []string{"-A", "PREROUTING", "-j", chain}},
	} {
		bad := append(slices.Clone(rows), row)
		if _, err := syntheticBaselineExactPresence(bad, plan, 0); err == nil {
			t.Fatal("same owned namespace in a foreign family/table accepted")
		}
	}
	for _, tokens := range [][]string{
		{"-A", chain, "-j", "ACCEPT"},
		{"-A", "FOREIGN", "-g", chain},
		{"-A", "PREROUTING", "--jump", chain},
		{"-A", "PREROUTING", "-j", chain},
		plan.Effects[1].Add[2:], // duplicate of a different requested index
		plan.Effects[3].Add[2:],
	} {
		bad := append(slices.Clone(rows), backendInventoryRow{Family: 4, Table: "nat", Tokens: slices.Clone(tokens)})
		if _, err := syntheticBaselineExactPresence(bad, plan, 0); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal("foreign/duplicate owner accepted", tokens, err)
		}
	}
}

func TestSyntheticBaselineKernelRejectsMalformedCompilerPayload(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	for _, malformed := range []PolicyEffectPlan{
		{}, {Generation: plan.Generation, Effects: []PolicyEffect{{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat"}}}},
		{Generation: plan.Generation, Effects: plan.Effects[:3]},
	} {
		if _, err := syntheticBaselineExactPresence(rows, malformed, 0); err == nil {
			t.Fatal("malformed payload accepted")
		}
		if err := syntheticBaselinePreDNATEquivalent(rows, malformed); err == nil {
			t.Fatal("malformed equivalence accepted")
		}
	}
	mutations := []func(*PolicyEffectPlan){
		func(p *PolicyEffectPlan) { p.Effects[1].Delete[9] = "1.1.1.1" },
		func(p *PolicyEffectPlan) { p.Effects[2].Needs = []int{0} },
		func(p *PolicyEffectPlan) { p.Effects[3].Add[19] = "8443" },
		func(p *PolicyEffectPlan) { p.Effects[2].Add[7] = "192.168.1.0/24" },
		func(p *PolicyEffectPlan) { p.Effects[1].Add[9] = "127.0.0.1" },
	}
	for _, mutate := range mutations {
		copy, _, err := copyPolicyEffectPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&copy)
		if _, err := syntheticBaselineExactPresence(rows, copy, 0); err == nil {
			t.Fatal("widened compiler payload accepted")
		}
	}
}

func TestSyntheticBaselineKernelNativeRenderingStillRequiresExactTuple(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	chain := plan.Effects[0].Add[3]
	for i := 5; i < 7; i++ {
		port := plan.Effects[i-3].Add[19]
		rows[i].Tokens = []string{"-A", "PREROUTING", "-s", "192.168.1.42", "-d", "198.18.0.1/32", "-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", "02:00:00:00:00:02", "-m", "tcp", "--dport", port, "-j", chain}
	}
	if count, err := syntheticBaselineExactPresence(rows, plan, 2); err != nil || count != 1 {
		t.Fatal("native base order refused", count, err)
	}
	if err := syntheticBaselinePreDNATEquivalent(rows, plan); err != nil {
		t.Fatal("own native selectors treated as foreign destination predicates", err)
	}
	macPlan, _, err := copyPolicyEffectPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{2, 3} {
		macPlan.Effects[i].Add[13] = "02:ab:cd:ef:01:02"
		macPlan.Effects[i].Delete[13] = "02:ab:cd:ef:01:02"
	}
	macRows := slices.Clone(rows)
	for _, i := range []int{5, 6} {
		macRows[i].Tokens = slices.Clone(rows[i].Tokens)
		macRows[i].Tokens[13] = "02:AB:CD:EF:01:02"
	}
	if _, err := syntheticBaselineExactPresence(macRows, macPlan, 2); err != nil {
		t.Fatal("canonical MAC case refused", err)
	}
	for _, tail := range [][]string{{"-m", "comment", "--comment", "owner"}, {"-m", "tcp"}, {"--dport", "80"}} {
		bad := slices.Clone(rows)
		bad[5].Tokens = append(slices.Clone(rows[5].Tokens), tail...)
		if _, err := syntheticBaselineExactPresence(bad, plan, 0); err == nil {
			t.Fatal("extra native rule syntax accepted", tail)
		}
	}
}

func TestSyntheticBaselineKernelDeletesOnlyAfterActualChildAbsence(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	for _, index := range []int{0, 1} {
		if err := syntheticBaselineDeletionReady(rows, plan, index); err == nil {
			t.Fatal("live child allowed parent deletion", index)
		}
	}
	if err := syntheticBaselineDeletionReady(rows, plan, 3); err != nil {
		t.Fatal("leaf dependency check refused", err)
	}
	if err := syntheticBaselineDeletionReady(rows[:5], plan, 1); err != nil {
		t.Fatal("removed selectors still held body", err)
	}
	if err := syntheticBaselineDeletionReady(rows[:4], plan, 0); err != nil {
		t.Fatal("removed body still held chain", err)
	}
	foreign := append(slices.Clone(rows[:4]), backendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "FOREIGN", "-j", plan.Effects[0].Add[3]}})
	if err := syntheticBaselineDeletionReady(foreign, plan, 0); err == nil {
		t.Fatal("foreign reference allowed deletion")
	}
}

func TestSyntheticBaselinePreDNATApplicableDestinationAndConntrackRefuse(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	if err := syntheticBaselinePreDNATEquivalent(rows, plan); err != nil {
		t.Fatal(err)
	}
	for _, tokens := range [][]string{
		{"-A", "PREROUTING", "-d", "93.184.215.14/32", "-j", "MARK", "--set-xmark", "1/1"},
		{"-A", "PREROUTING", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"},
		{"-A", "PREROUTING", "-j", "CONNMARK", "--restore-mark", "1"},
		{"-A", "PREROUTING", "-m", "set", "--match-set", "foreign", "-j", "ACCEPT"},
		{"-A", "PREROUTING", "-m", "unreviewed", "-j", "ACCEPT"},
		{"-A", "PREROUTING", "-j", "DNAT", "--to-destination", "1.1.1.1"},
		{"-A", "PREROUTING", "-j", "UNDECLARED"},
	} {
		bad := append(slices.Clone(rows), backendInventoryRow{Family: 4, Table: "mangle", Tokens: tokens})
		if err := syntheticBaselinePreDNATEquivalent(bad, plan); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal("unknown applicable hook accepted", tokens, err)
		}
	}
}

func TestSyntheticBaselinePreDNATKnownNonmatchingConjunctOnly(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	for _, predicate := range [][]string{
		{"-p", "udp", "--dport", "53"}, {"-p", "tcp", "--dport", "53"},
		{"-s", "192.168.2.0/24"}, {"!", "-s", "192.168.1.42/32"},
		{"-i", "br1"}, {"--mac-source", "02:00:00:00:00:03"},
	} {
		tokens := append([]string{"-A", "PREROUTING", "-d", "192.168.1.1/32"}, predicate...)
		tokens = append(tokens, "-j", "DNAT", "--to-destination", "127.0.0.1:53")
		view := append(slices.Clone(rows), backendInventoryRow{Family: 4, Table: "nat", Tokens: tokens})
		if err := syntheticBaselinePreDNATEquivalent(view, plan); err != nil {
			t.Fatal("unrelated DNS/source rule refused", predicate, err)
		}
	}
	for _, predicate := range [][]string{{"--dport", "80:443"}, {"!", "-p", "udp"}, {"-i", "br+"}, {"-s", "192.168.1.0/24"}} {
		tokens := append([]string{"-A", "PREROUTING", "-d", "1.1.1.1/32"}, predicate...)
		tokens = append(tokens, "-j", "MARK", "--set-mark", "1")
		view := append(slices.Clone(rows), backendInventoryRow{Family: 4, Table: "mangle", Tokens: tokens})
		if err := syntheticBaselinePreDNATEquivalent(view, plan); err == nil {
			t.Fatal("potentially applicable destination rule skipped", predicate)
		}
	}
}

func TestSyntheticBaselinePreDNATReachableChainsAndMissingCoverage(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	good := append(slices.Clone(rows),
		backendInventoryRow{Family: 4, Table: "mangle", Tokens: []string{"-N", "SOURCE"}},
		backendInventoryRow{Family: 4, Table: "mangle", Tokens: []string{"-A", "PREROUTING", "-g", "SOURCE"}},
		backendInventoryRow{Family: 4, Table: "mangle", Tokens: []string{"-A", "SOURCE", "-s", "192.168.1.0/24", "-m", "mark", "--mark", "1/1", "-j", "MARK", "--set-xmark", "2/2"}},
		backendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "OUTPUT", "-d", "1.1.1.1", "-j", "DNAT", "--to-destination", "127.0.0.1"}},
	)
	if err := syntheticBaselinePreDNATEquivalent(good, plan); err != nil {
		t.Fatal(err)
	}
	cycle := append(slices.Clone(good), backendInventoryRow{Family: 4, Table: "mangle", Tokens: []string{"-A", "SOURCE", "-j", "PREROUTING"}})
	if err := syntheticBaselinePreDNATEquivalent(cycle, plan); err == nil {
		t.Fatal("reachable cycle accepted")
	}
	if err := syntheticBaselinePreDNATEquivalent(rows[1:], plan); err == nil {
		t.Fatal("missing raw hook accepted")
	}
	if _, err := (*syntheticBaselineKernelInspector)(nil).ExactPresence(context.Background(), 0); err == nil {
		t.Fatal("nil actual reader accepted")
	}
	if _, err := new(syntheticBaselineKernelInspector).ExactPresence(context.Background(), 0); err == nil {
		t.Fatal("snapshot-shaped reader accepted")
	}
}
