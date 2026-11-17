package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestMihomoManualPlanningPreservesExactCIDRSet(t *testing.T) {
	original := []string{"8.8.8.0/24", "1.1.1.0/24"}
	for _, tc := range []struct {
		name string
		got  []string
		want bool
	}{
		{"catalogue-order", []string{"8.8.8.0/24", "1.1.1.0/24"}, true},
		{"compiler-order", []string{"1.1.1.0/24", "8.8.8.0/24"}, true},
		{"extra-prefix", []string{"1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"}, false},
		{"missing-prefix", []string{"1.1.1.0/24"}, false},
		{"broader-prefix", []string{"1.1.1.0/24", "8.8.0.0/16"}, false},
		{"duplicate", []string{"1.1.1.0/24", "8.8.8.0/24", "8.8.8.0/24"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if sameMihomoNodePlanningCIDRs(tc.got, original) != tc.want {
				t.Fatal("scope set changed")
			}
		})
	}
	if original[0] != "8.8.8.0/24" || sameMihomoNodePlanningCIDRs([]string{"1.1.1.0/24"}, []string{"1.1.1.0/24", "1.1.1.0/24"}) {
		t.Fatal("comparison changed catalogue or compacted duplicate authority")
	}
}

func TestMihomoManualPlanningInvalidTicketNeverReachesSources(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := &App{Dataplane: dataplane.New(t.TempDir())}
	p := &mihomoNodePlanningTicket{bound: &mihomoNodeBinding{app: a}, manager: a.Dataplane}
	p.self = p
	p.ctx = context.WithValue(ctx, mihomoNodePlanningKey{}, p)
	// Missing original node must fail even with a structurally plausible ticket.
	p.open.Store(true)
	if !errors.Is(p.current(p.ctx, a, []dataplane.Route{{}}), dataplane.ErrReviewChanged) {
		t.Fatal("reconstructed source accepted")
	}
	for _, value := range []*mihomoNodePlanningTicket{nil, {}, p} {
		if !errors.Is(value.current(ctx, a, nil), dataplane.ErrReviewChanged) {
			t.Fatal("invalid ticket reached source callback")
		}
	}

}

func TestMihomoManualPlanningBindingRejectsSameRevisionDrift(t *testing.T) {
	for _, kind := range []string{"config", "catalog", "node-store"} {
		t.Run(kind, func(t *testing.T) {
			a, id, _ := nodeApplyFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			node, err := dataplane.ReviewNodeDefaultSource(ctx, a.Nodes, "mihomo:"+id)
			if err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			b := &mihomoNodeBinding{app: a, store: a.Store, node: node, before: before, catalog: mihomoNodeCatalogClone(a.catalogSnapshot()), service: defaultRouteCloneCatalogService(a.catalogSnapshot().Services[0]), profile: "wan-0123456789ab"}
			b.self = b
			if err := b.current(ctx); err != nil {
				t.Fatal("original planning source", err)
			}
			switch kind {
			case "config":
				b.before.SafeMode = !b.before.SafeMode
			case "catalog":
				a.Catalog.Services[0].Name = "Changed without configuration revision"
			case "node-store":
				if err := a.Nodes.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if a.Store.Get().Revision != before.Revision {
				t.Fatal("test did not preserve base revision")
			}
			if err := b.current(ctx); err == nil {
				t.Fatal("same-revision/source drift retained compiler fact")
			}
		})
	}
}
