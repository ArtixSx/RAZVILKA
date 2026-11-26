package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Socket-free original Manager/scope lifecycle model. The physical reader is
// explicitly a model; no native tool, listener, capture or publication exists.
func syntheticExecutionModel(t *testing.T) (*Manager, *ScopedDNSAdapter, Plan, *executionResourceScope, context.Context) {
	t.Helper()
	transport, domain := syntheticTransportModelFixture(t)
	plan, err := BuildAt(Input{DomainPolicy: domain, SyntheticDNS: transport}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.Adapters = []string{scopedDNSAdapterID}
	plan.NetworkProfileID = "wan-123456789abc"
	root := filepath.Join(t.TempDir(), "dataplane")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(root)
	m.FreshProfile = func(context.Context) (string, error) { return plan.NetworkProfileID, nil }
	provider := new(netidentity.Provider)
	identity := &networkPolicyIdentity{provider: provider, value: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "01234567-89ab-cdef-0123-456789abcdef", Inode: 12345}}
	identity.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
		return use(c, identity.value)
	}
	if err := m.Register(&NetworkPolicyAdapter{identity: identity}); err != nil {
		t.Fatal(err)
	}
	adapter := NewScopedDNSAdapter(context.Background(), new(dnscontrol.Manager), root)
	adapter.InactivityIdentity = provider
	if err := m.Register(adapter); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(WithReviewGuard(context.Background(), func(c context.Context) error { return c.Err() }), time.Minute)
	t.Cleanup(cancel)
	execution := &Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying"}
	txroot := filepath.Join(root, "transactions", plan.PlanID)
	if err := m.prepareExecutionRoot(txroot); err != nil {
		t.Fatal(err)
	}
	scope, err := m.newExecutionResourceScope(ctx, plan, scopedDNSAdapterID, execution, txroot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.close() })
	return m, adapter, plan, scope, ctx
}

func TestSyntheticExecutionBindingRequiresSameOriginalManagerScope(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	for _, c := range []context.Context{nil, ctx, context.Background(), withSyntheticExecutionRegistrar(context.Background(), scope)} {
		if _, err := m.BindSyntheticDNSExecution(c, a, plan); err == nil {
			t.Fatal("definition/context substituted for finite original issuer")
		}
	}
	held := withSyntheticExecutionRegistrar(scope.contextWith(ctx), scope)
	b, err := m.BindSyntheticDNSExecution(held, a, plan)
	if err != nil {
		t.Fatal(err)
	}
	copy := cloneExecutionResourcePlan(plan)
	copy.SyntheticDNS.CaptureEndpoint = "192.168.1.1:10444"
	if _, err := m.BindSyntheticDNSExecution(held, a, copy); err == nil {
		t.Fatal("changed frozen plan accepted")
	}
	if _, err := New(m.StateRoot).BindSyntheticDNSExecution(held, a, plan); err == nil {
		t.Fatal("same path revived a different Manager")
	}
	if _, err := m.BindSyntheticDNSExecution(held, NewScopedDNSAdapter(a.lifetime, a.DNS, m.StateRoot), plan); err == nil {
		t.Fatal("same adapter metadata revived a different owner")
	}
	if _, err := b.baselineInspector(held, new(dnscontrol.SyntheticDNSMapping), new(BackendInventory)); err == nil {
		t.Fatal("metadata-shaped mapping/readback accepted")
	}
	if err := scope.close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Current(context.WithoutCancel(held)); err == nil {
		t.Fatal("finite scope close revived through cancellation detachment")
	}
}

func TestSyntheticExecutionBindingClosingChecksSourceAndRegistryDrift(t *testing.T) {
	for _, kind := range []string{"dns", "root", "registry", "network", "guard"} {
		t.Run(kind, func(t *testing.T) {
			m, a, plan, scope, ctx := syntheticExecutionModel(t)
			held := withSyntheticExecutionRegistrar(scope.contextWith(ctx), scope)
			b, err := m.BindSyntheticDNSExecution(held, a, plan)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "dns":
				a.DNS = new(dnscontrol.Manager)
			case "root":
				a.StateRoot = filepath.Join(m.StateRoot, "other")
			case "registry":
				if err := m.Register(&fakeAdapter{id: "model-other"}); err != nil {
					t.Fatal(err)
				}
			case "network":
				scope.networkIdentity.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					other := scope.networkIdentity.value
					other.Inode++
					return use(c, other)
				}
			case "guard":
				scope.guard = func(context.Context) error { a.DNS = new(dnscontrol.Manager); return nil }
			}
			if err := b.Current(held); err == nil {
				t.Fatal("original source/closing drift accepted")
			}
		})
	}
	if err := new(SyntheticDNSExecutionBinding).Current(context.Background()); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatal("empty binding granted authority", err)
	}
}
