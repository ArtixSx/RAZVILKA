package dataplane

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestSyntheticBaselinePreparedKernelRequiresOneWholeImage(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	if err := syntheticBaselinePreparedKernel(rows, plan); err != nil {
		t.Fatal("exact complete comparison model refused", err)
	}
	for missing := range plan.Effects {
		partial := slices.Clone(rows)
		partial = append(partial[:missing+3:missing+3], partial[missing+4:]...)
		if err := syntheticBaselinePreparedKernel(partial, plan); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal("incomplete kernel image became prepared", missing, err)
		}
	}
	// Each individual effect can be present in a DIFFERENT incomplete image.
	// Those four successful observations do not establish one prepared graph.
	for index := range plan.Effects {
		split := append(slices.Clone(rows[:3]), rows[index+3])
		if count, err := syntheticBaselineExactPresence(split, plan, index); err != nil || count != 1 {
			t.Fatal("model did not reproduce split presence", index, count, err)
		}
		if err := syntheticBaselinePreparedKernel(split, plan); err == nil {
			t.Fatal("split presence observations manufactured prepared graph")
		}
	}
}

func TestSyntheticBaselinePreparedKernelChecksWholeOwnerAndFirmware(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	chain := plan.Effects[0].Add[3]
	for _, row := range []backendInventoryRow{
		rows[4], // Duplicate exact DNAT body, even if every selector is present.
		{Family: 4, Table: "nat", Tokens: []string{"-A", chain, "-j", "ACCEPT"}},
		{Family: 6, Table: "nat", Tokens: []string{"-N", chain}},
		{Family: 4, Table: "filter", Tokens: []string{"-A", "INPUT", "-j", chain}},
		{Family: 4, Table: "raw", Tokens: []string{"-A", "PREROUTING", "-j", "NOTRACK"}},
		{Family: 4, Table: "mangle", Tokens: []string{"-A", "PREROUTING", "-d", "93.184.215.14/32", "-j", "MARK", "--set-mark", "1"}},
		{Family: 4, Table: "nat", Tokens: []string{"-A", "PREROUTING", "-j", "DNAT", "--to-destination", "1.1.1.1"}},
	} {
		bad := append(slices.Clone(rows), row)
		if err := syntheticBaselinePreparedKernel(bad, plan); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal("foreign/duplicate/earlier firmware effect accepted", row.Table, err)
		}
	}
	equivalent := append(slices.Clone(rows), backendInventoryRow{Family: 4, Table: "mangle", Tokens: []string{"-A", "PREROUTING", "-j", "MARK", "--set-mark", "1"}})
	if err := syntheticBaselinePreparedKernel(equivalent, plan); err != nil {
		t.Fatal("existing destination-independent firmware mark changed equivalence", err)
	}
	for missing := range 3 {
		bad := append(slices.Clone(rows[:missing:missing]), rows[missing+1:]...)
		if err := syntheticBaselinePreparedKernel(bad, plan); err == nil {
			t.Fatal("missing built-in hook coverage accepted", missing)
		}
	}
	if err := syntheticBaselinePreparedKernel(rows, PolicyEffectPlan{}); err == nil {
		t.Fatal("uncompiled definition accepted")
	}
}

func TestSyntheticBaselinePreparedKernelRefusesUnoriginalMappingBeforeReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plan, _ := syntheticBaselineKernelModel(t)
	i := &syntheticBaselineKernelInspector{plan: plan, mapping: new(dnscontrol.SyntheticDNSMapping), backend: new(BackendInventory)}
	i.self = i
	for _, inspector := range []*syntheticBaselineKernelInspector{nil, {}, i} {
		if err := inspector.CheckPrepared(ctx); err == nil {
			t.Fatal("metadata mapping/reader manufactured prepared capability")
		}
	}
	for _, c := range []context.Context{nil, context.Background()} {
		if err := i.CheckPrepared(c); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal("unbounded prepared check entered original reader", err)
		}
	}
}
