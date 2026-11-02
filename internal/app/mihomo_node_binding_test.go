package app

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// This exercises the original private commit cursor/Store CAS only; native
// validation, service/TUN proof and Manager admission are separate requirements.
func TestMihomoNodeBindingCommitRetainsExactImageAndUndoOwnership(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "foreign-writer"}[foreign], func(t *testing.T) {
			a, id, _ := nodeApplyFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			node, err := dataplane.ReviewNodeDefaultSource(ctx, a.Nodes, "mihomo:"+id)
			if err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			service := a.catalogSnapshot().Services[0]
			plan := dataplane.Plan{Revision: before.Revision + 1, Routes: []dataplane.Route{{ServiceID: service.ID, LogicalServiceID: service.ID, Selected: "mihomo:" + id, Resolved: "mihomo:" + id, Sources: []string{"192.168.1.42/32"}}}}
			b := &mihomoNodeBinding{app: a, store: a.Store, node: node, before: before, catalog: mihomoNodeCatalogClone(a.catalogSnapshot()), service: service, profile: "wan-0123456789ab", plan: plan}
			b.self = b
			if _, err = b.commit(ctx); err == nil || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("foreign context committed")
			}
			owned := context.WithValue(ctx, mihomoNodeBindingKey{}, b)
			undo, err := b.commit(owned)
			if err != nil {
				t.Fatal(err)
			}
			captured := b.after.Load()
			if captured == nil || captured.Revision != before.Revision+1 || !reflect.DeepEqual(*captured, a.Store.Get()) || b.current(owned) != nil {
				t.Fatal("exact acknowledged image missing")
			}
			if foreign {
				if err = a.Store.UpdateService(service.ID, before.Services[service.ID]); err != nil {
					t.Fatal(err)
				}
				if b.current(owned) == nil || undo() == nil || b.after.Load() != captured {
					t.Fatal("foreign writer adopted or failed undo cleared cursor")
				}
			} else {
				if err = undo(); err != nil || b.after.Load() != nil || !reflect.DeepEqual(before, a.Store.Get()) || b.current(owned) != nil {
					t.Fatal("exact undo did not restore original binding", err)
				}
			}
		})
	}
}
