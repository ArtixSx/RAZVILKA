package dnscontrol

import (
	"context"
	"testing"
	"time"
)

func TestSyntheticDNSAdapterRequiresOriginalFrozenResolverAndSameSource(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plan := CloneNetworkPolicyDNSPlan(f.r.frozenPlan)
	manager := f.r.defaultDNS.manager
	if err := f.r.CheckSyntheticAdapterDefinition(ctx, manager, plan, f.control, f.definition); err != nil {
		t.Fatal(err)
	}
	copy := *f.r
	if err := copy.CheckSyntheticAdapterDefinition(ctx, manager, plan, f.control, f.definition); err == nil {
		t.Fatal("copied resolver revived original adapter source")
	}
	for _, r := range []*NetworkPolicyDNSResolver{nil, new(NetworkPolicyDNSResolver), {authority: f.r.authority, defaultDNS: f.r.defaultDNS, operations: f.gate}} {
		if err := r.CheckSyntheticAdapterDefinition(ctx, manager, plan, f.control, f.definition); err == nil {
			t.Fatal("loose/copied metadata created original ForPlan binding")
		}
	}
	if err := f.r.CheckSyntheticAdapterDefinition(ctx, new(Manager), plan, f.control, f.definition); err == nil {
		t.Fatal("different DNS Manager accepted")
	}
	changed := CloneNetworkPolicyDNSPlan(plan)
	changed.Digest = "changed"
	if err := f.r.CheckSyntheticAdapterDefinition(ctx, manager, changed, f.control, f.definition); err == nil {
		t.Fatal("different frozen plan accepted")
	}
	s := f.source(t, nil)
	if err := s.CheckAdapterBinding(ctx, manager, plan, f.control, f.root, f.definition); err != nil {
		t.Fatal(err)
	}
	wrong := f.definition
	wrong.MAC = "02:00:00:00:00:99"
	if err := s.CheckAdapterBinding(ctx, manager, plan, f.control, f.root, wrong); err == nil {
		t.Fatal("different original device tuple accepted")
	}
	if err := s.CheckAdapterBinding(ctx, manager, plan, f.control, f.root+"-other", f.definition); err == nil {
		t.Fatal("different reservation root accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAdapterBinding(ctx, manager, plan, f.control, f.root, f.definition); err == nil {
		t.Fatal("closed source granted adapter admission")
	}
}
