package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Pure original-compiler/capture models. The test-only image representation
// cannot make the zero concrete provider read a kernel or issue any grant.
func nfqwsScopedStockImageFixture(t *testing.T, present bool) (*NFQWSScopedBinding, *NFQWSScopedPlan, nfqwsScopedReadImage) {
	t.Helper()
	plan, spec, _ := nfqwsScopedDirectFixture(t, "ipv4")
	spec.NetNamespace = ""
	spec.NetworkIdentity = &netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: spec.BootID, PlatformReviewSHA256: backendNFTStockScopeSHA256}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := nfqwsScopedBindingFixture(t)
	root := t.TempDir()
	b.Tools.IPTables, b.Tools.IP6Tables = filepath.Join(root, "iptables"), filepath.Join(root, "ip6tables")
	provider := &netidentity.Provider{}
	runner := backendInventoryTestRunner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("model only; no kernel capture")
	})
	b.Runner = runner
	inventory, err := NewReviewedStockNC1812BackendInventory(provider, BackendInventoryTools{Runner: runner, IPTables: b.Tools.IPTables, IP6Tables: b.Tools.IP6Tables,
		ReviewSHA256: strings.Repeat("a", 64), Check: func(context.Context, netidentity.Identity) error { return errors.New("model only; no tool grant") }})
	if err != nil {
		t.Fatal(err)
	}
	b, err = NewTypedNFQWSScopedBinding(provider, inventory, *b)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nfqwsDirectStockReviewedVendorFixture()
	snapshot.Scope.Network = *spec.NetworkIdentity
	snapshot.IPTables, snapshot.IP6Tables = b.Tools.IPTables, b.Tools.IP6Tables
	if present {
		for _, effect := range p.mixed.Effects {
			family := 4
			if effect.Tool == PolicyEffectIP6Tables {
				family = 6
			}
			snapshot.Rows = append(snapshot.Rows, nfqwsDirectStockTestRow(family, "mangle", slices.Clone(effect.Add[2:])...))
		}
	}
	rules, err := nfqwsScopedInventoryRules(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return b, p, nfqwsScopedReadImage{rules: rules, capture: &nfqwsScopedReadCapture{source: b.network, plan: p, snapshot: snapshot}}
}

func nfqwsScopedStockRefreshProjection(t *testing.T, image *nfqwsScopedReadImage) {
	t.Helper()
	var err error
	image.rules, err = nfqwsScopedInventoryRules(image.capture.snapshot)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNFQWSScopedStockReadImageExactCountsPreserveOriginalModes(t *testing.T) {
	for _, present := range []bool{false, true} {
		b, p, image := nfqwsScopedStockImageFixture(t, present)
		modes := []nfqwsScopedReadMode{nfqwsScopedBeforeStart, nfqwsScopedAbsent, nfqwsScopedNew}
		wanted := 0
		if present {
			modes, wanted = []nfqwsScopedReadMode{nfqwsScopedComplete, nfqwsScopedPartial, nfqwsScopedCleanup}, 1
		}
		for _, mode := range modes {
			counts, err := b.ruleCountsImage(p, image, mode)
			if err != nil || len(counts) != len(p.mixed.Effects) {
				t.Fatal("exact observed image rejected", present, mode, err)
			}
			for _, count := range counts {
				if count != wanted {
					t.Fatal("stock comparison changed an owned effect count")
				}
			}
		}
		if _, err := p.ruleCounts(image.rules, nfqwsScopedPartial); err == nil {
			t.Fatal("bare map borrowed the typed stock comparison")
		}
		if present {
			if _, err := b.ruleCountsImage(p, image, nfqwsScopedBeforeStart); err == nil {
				t.Fatal("present capture passed original absence mode")
			}
		} else {
			if _, err := b.ruleCountsImage(p, image, nfqwsScopedComplete); err == nil {
				t.Fatal("stock rows manufactured completed owned effects")
			}
		}
		if _, err := b.network.rules(context.Background(), p); err == nil {
			t.Fatal("model provider minted an actual per-read capture")
		}
	}
	b, p, image := nfqwsScopedStockImageFixture(t, false)
	e := p.mixed.Effects[0]
	image.capture.snapshot.Rows = append(image.capture.snapshot.Rows, nfqwsDirectStockTestRow(4, "mangle", slices.Clone(e.Add[2:])...))
	nfqwsScopedStockRefreshProjection(t, &image)
	counts, err := b.ruleCountsImage(p, image, nfqwsScopedPartial)
	if err != nil || counts[0] != 1 {
		t.Fatal("exact observed optional partial prefix rejected", err)
	}
	if _, err := b.ruleCountsImage(p, image, nfqwsScopedComplete); err == nil {
		t.Fatal("partial prefix became complete through stock rows")
	}
}

func TestNFQWSScopedStockReadImageRejectsDifferentSourceAndChangedProjection(t *testing.T) {
	cases := map[string]func(*NFQWSScopedBinding, *NFQWSScopedPlan, *nfqwsScopedReadImage){
		"missing-capture": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) { image.capture = nil },
		"other-binding": func(b *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			other := *b.network
			image.capture.source = &other
		},
		"other-plan": func(_ *NFQWSScopedBinding, p *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			other := *p
			image.capture.plan = &other
		},
		"wrong-queue": func(_ *NFQWSScopedBinding, p *NFQWSScopedPlan, _ *nfqwsScopedReadImage) { p.resources.Queue++ },
		"other-network": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.Scope.Network.BootID = "11234567-89ab-cdef-0123-456789abcdef"
		},
		"other-tool-review": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.Scope.ToolReviewID = strings.Repeat("b", 64)
		},
		"other-tools": func(b *NFQWSScopedBinding, _ *NFQWSScopedPlan, _ *nfqwsScopedReadImage) { b.Tools.IPTables += "-other" },
		"capture-other-tool": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.IP6Tables += "-other"
		},
		"changed-reader-provider": func(b *NFQWSScopedBinding, _ *NFQWSScopedPlan, _ *nfqwsScopedReadImage) {
			b.network.inventory.reader.Provider = &netidentity.Provider{}
		},
		"lost-tool-check": func(b *NFQWSScopedBinding, _ *NFQWSScopedPlan, _ *nfqwsScopedReadImage) {
			b.network.inventory.reader.CheckTools = nil
		},
		"projection-hides-row": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.rules[PolicyEffectIPTables]["mangle"] = image.rules[PolicyEffectIPTables]["mangle"][:1]
		},
		"projection-extra-row": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.rules[PolicyEffectIPTables]["mangle"] = append(image.rules[PolicyEffectIPTables]["mangle"], []string{"-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1104"})
		},
		"capture-changed-after-projection": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.Rows[0].Tokens[2] = "DROP"
		},
		"incomplete-capture": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.Coverage.RegisteredTablesComplete = false
		},
		"native-nft-present": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.NFTState = BackendNFTPresent
		},
		"oversized-capture": func(_ *NFQWSScopedBinding, _ *NFQWSScopedPlan, image *nfqwsScopedReadImage) {
			image.capture.snapshot.Rows = make([]BackendInventoryRow, backendClassicRows+1)
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			b, p, image := nfqwsScopedStockImageFixture(t, true)
			alter(b, p, &image)
			if _, err := b.ruleCountsImage(p, image, nfqwsScopedComplete); !errors.Is(err, ErrNFQWSScopedOwner) {
				t.Fatal("changed local image/provenance passed", err)
			}
		})
	}
}

func TestNFQWSScopedStockReadImageKeepsGraphAndBodyPredicates(t *testing.T) {
	cases := map[string]func(*NFQWSScopedPlan, *BackendInventorySnapshot){
		"extra-owned-copy": func(p *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", slices.Clone(p.mixed.Effects[len(p.mixed.Effects)-1].Add[2:])...))
		},
		"unowned-body": func(p *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", p.chains[0].name, "-j", "RETURN"))
		},
		"unowned-incoming-reference": func(p *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "INPUT", "-j", p.chains[0].name))
		},
		"stock-forward-path": func(_ *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "local_bridge"))
		},
		"foreign-managed-number": func(p *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			fields := s.Rows[nfqwsDirectStockTestQueueIndex(*s, 4)].Tokens
			fields[len(fields)-1] = strconv.Itoa(int(p.resources.Queue))
		},
		"different-owned-body-order": func(p *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			var positions []int
			for i, row := range s.Rows {
				if row.Tokens[0] == "-A" && row.Tokens[1] == p.chains[0].name {
					positions = append(positions, i)
				}
			}
			if len(positions) < 2 {
				panic("original compiler fixture requires two bodies")
			}
			s.Rows[positions[0]], s.Rows[positions[1]] = s.Rows[positions[1]], s.Rows[positions[0]]
		},
		"foreign-other-table": func(_ *NFQWSScopedPlan, s *BackendInventorySnapshot) {
			s.Rows = append(s.Rows, nfqwsDirectStockTestRow(6, "filter", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1200"))
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			b, p, image := nfqwsScopedStockImageFixture(t, true)
			alter(p, &image.capture.snapshot)
			nfqwsScopedStockRefreshProjection(t, &image)
			if _, err := b.ruleCountsImage(p, image, nfqwsScopedComplete); !errors.Is(err, ErrNFQWSScopedOwner) {
				t.Fatal("fresh complete graph or original body constraint waived", err)
			}
		})
	}
}

func TestNFQWSScopedStockReadImageUntypedAndFinalBoundaryStayStrict(t *testing.T) {
	_, _, p := nfqwsScopedDirectFixture(t, "ipv4")
	reads, predicates := 0, 0
	b := &NFQWSScopedBinding{Tools: PolicyEffectTools{IPTables: "iptables", IP6Tables: "ip6tables"}}
	b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error { predicates++; return nil }
	b.Runner = backendInventoryTestRunner(func(_ context.Context, command string, args ...string) ([]byte, error) {
		reads++
		if predicates == 2 && command == "iptables" && len(args) == 3 && args[1] == "mangle" {
			return []byte("-P FORWARD ACCEPT\n-A OUTPUT -j NFQUEUE --queue-num 1104\n"), nil
		}
		return []byte("-P FORWARD ACCEPT\n"), nil
	})
	image, err := b.readFinalRules(context.Background(), p)
	if err != nil || reads != 20 || predicates != 2 || image.capture != nil {
		t.Fatal("fresh final image or untyped bracket changed", reads, predicates, err)
	}
	before := cloneNetworkPolicyInventoryTestRows([]BackendInventoryRow{{Family: 4, Table: "mangle", Tokens: image.rules[PolicyEffectIPTables]["mangle"][1]}})
	if _, err := b.ruleCountsImage(p, image, nfqwsScopedBeforeStart); !errors.Is(err, ErrNFQWSScopedOwner) {
		t.Fatal("closing callback's new foreign queue inherited prior facts", err)
	}
	if !reflect.DeepEqual(before[0].Tokens, image.rules[PolicyEffectIPTables]["mangle"][1]) {
		t.Fatal("classification rewrote the final image")
	}
}
