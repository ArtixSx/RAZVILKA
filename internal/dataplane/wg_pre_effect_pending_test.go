package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

// Private source/tool leaves only. Every read still consumes the original
// production command admission; its begin syscall and reply are models.
// There is no native child, kernel observation, handshake or mutation proof.
type wgPreEffectToolModel struct {
	review string
	reads  int
}

func (m *wgPreEffectToolModel) CheckWG(ctx context.Context, _ netidentity.Identity) error {
	return ctx.Err()
}
func (m *wgPreEffectToolModel) RunWG(ctx context.Context, grant WGCommandAdmission, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	wan := strings.Contains(joined, "route get ")
	link := len(args) == 4 && args[0] == "link" && args[1] == "show" && args[2] == "dev"
	if !wan && !link {
		return nil, errors.New("WG no-effect model refused a non-read command")
	}
	if err := grant.WithStart(ctx, name, args, m.review, func() error { return nil }); err != nil {
		return nil, err
	}
	m.reads++
	if link {
		return nil, errors.New("modeled original link absence")
	}
	return []byte(`[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`), ctx.Err()
}

// Actual production WG adapter, Manager scope/compensation, profile Store,
// original source/material/control and both retained authored execution FDs.
// NI/WAN/LAN/kernel/tool leaves are explicit models. In particular the LAN
// inventory model is not a WG consumer RollbackVerifier.
func wgPreEffectPendingFixture(t *testing.T) (*Manager, *retainedWGExecution, context.Context, *operationgate.ExclusiveCleanupReview, *lanPolicyReceiptModel) {
	t.Helper()
	base := t.TempDir()
	m := New(filepath.Join(base, "dataplane"))
	if err := os.MkdirAll(m.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(base, "stage"), filepath.Join(base, "backups"))
	configs.LiveRoot = filepath.Join(base, "live")
	a := NewWireGuardAdapter(configs, m.StateRoot)
	profiles := wireguardprofile.New(filepath.Join(base, "profiles"))
	a.Profiles = profiles
	profile, err := profiles.Put(t.Context(), "server", "Imported test profile", strings.ReplaceAll(testOwnWireGuardProfile(""), "vpn.example.com", "1.1.1.1"), "")
	if err != nil {
		t.Fatal(err)
	}
	toolsModel := &wgPreEffectToolModel{review: strings.Repeat("a", 64)}
	identity, current := networkPolicyIdentityFixture()
	provider := netidentity.NewProcProvider()
	identity.provider = provider
	// Distinct tool names preserve the production read-vs-mutation classifier;
	// this private runner implements the leaves and never executes these paths.
	tools := WGCommandTools{EngineID: "wireguard", WG: filepath.Join(base, "tools", "wg"), IP: filepath.Join(base, "tools", "ip"), IPTables: filepath.Join(base, "tools", "iptables"), IP6Tables: filepath.Join(base, "tools", "ip6tables"), ReviewSHA256: toolsModel.review, Identity: *current, Provider: provider, Runner: toolsModel}
	if err := a.BindWGCommandTools(tools); err != nil {
		t.Fatal(err)
	}
	b, lanModel, _ := lanReceiptBindingFixture(t)
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: b, InventoryCheck: func(c context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
		if got != identity.value || lan != nil && !reflect.DeepEqual(lan, lanModel.plan) {
			return ErrBackendInventoryUnknown
		}
		return c.Err()
	}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range []Adapter{gate, a} {
		if err := m.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	var admission operationgate.Gate
	ctx, release, err := admission.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	controlRoot := filepath.Join(base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := admission.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	reader, err := ReviewWGSourceRead(ctx, m, control, "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	capture, err := reader.CaptureProfile(ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	source, err := ReviewWGListSourceMaterial(ctx, reader, capture, catalog.Service{ID: "listed", Name: "Listed", Category: "fixture", Strategy: []string{"wireguard"}, CIDRs: []string{"1.1.1.0/24"}, ProbeURL: "https://1.1.1.1/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	material, err := ReviewWGOperationMaterial(ctx, m, control, lanModel.plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = material.Close() })
	if err := material.BindSourceReview(ctx, source); err != nil {
		t.Fatal(err)
	}
	ctx, err = material.Context(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-0123456789abcdef", Digest: strings.Repeat("b", 64), Revision: 1, Ready: true, NetworkProfileID: executionNetwork, Adapters: []string{NetworkPolicyAdapterID, "wireguard"}, LAN: CloneLANPolicyRuntime(lanModel.plan), Routes: []Route{{ServiceID: "listed", Selected: "wireguard:server", Resolved: "wireguard:server", CIDRs: []string{"1.1.1.0/24"}, Sources: []string{"192.168.1.0/24"}, Ingress: []string{"br0"}, NetworkPolicyGeneration: lanModel.plan.Generation, NetworkPolicyRole: "override", WireGuardProfileRevision: profile.Revision}}}
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	candidate := filepath.Join(m.StateRoot, "transactions", p.PlanID, NetworkPolicyAdapterID, "candidate.json")
	forwardCut := errors.New("modeled original forward fence after LAN Stage before WG Stage")
	ctx = WithReviewGuard(ctx, func(c context.Context) error {
		if material.IsCleanupContext(c) {
			return control.CurrentForCleanup(c)
		}
		if _, err := os.Stat(candidate); err == nil {
			lanModel.foreignRef = true
			return forwardCut
		}
		return control.Current(c)
	})
	result, err := m.Apply(ctx, p, nil)
	if err == nil || !errors.Is(err, forwardCut) || result.State != "rollback-failed" || result.RollbackVerified || !m.HasPendingManagedWG() {
		t.Fatal("actual WG no-effect failure not retained", result, err)
	}
	o := m.retainedWGOwner()
	if o == nil || o.scope.wgOwner.adapter != a || o.scope.wgOwner.mutationAttempted.Load() || len(result.Resources) != 0 {
		t.Fatal("model crossed WG mutation boundary")
	}
	t.Cleanup(func() { _ = o.scope.close() }) // Explicit no-mutation fixture teardown only.
	if o.scope.wgRecords.current(ctx, false) != nil {
		t.Fatal("original authored journal pair lost")
	}
	for _, step := range result.Steps {
		if step.Adapter == "wireguard" && (step.Phase == "stage" || step.Phase == "activate" || step.Phase == "verify-rollback") {
			t.Fatal("fixture invented WG phase/readback", step)
		}
	}
	lanModel.foreignRef = false
	return m, o, ctx, material.cleanup, lanModel
}

func TestWGPreEffectPendingProductionAdapterLacksIndependentVerifier(t *testing.T) {
	m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t)
	if _, ok := any(o.scope.wgOwner.adapter).(RollbackVerifier); ok {
		t.Fatal("WG verifier contract changed; update reachability test")
	}
	err := m.JoinPendingManagedWG(ctx, cleanup)
	var latest, transaction Execution
	for path, target := range map[string]*Execution{filepath.Join(m.StateRoot, "latest-execution.json"): &latest, filepath.Join(o.scope.root, "execution.json"): &transaction} {
		data, readErr := os.ReadFile(path)
		if readErr != nil || json.Unmarshal(data, target) != nil {
			t.Fatal(readErr)
		}
	}
	if latest.State != "rolled-back" || transaction.State != "rolled-back" || latest.RollbackVerified || transaction.RollbackVerified || !m.HasPendingManagedWG() || o.scope.wgCleanupJoined {
		t.Fatal("expected exact no-effect retry predicate/refusal boundary", latest, transaction, err)
	}
	// Desired eventual behavior requires a NEW independent original WG
	// consumer readback first. This honest RED must not be fixed merely by
	// dropping RollbackVerified or reusing wgCleanupJoined from another cycle.
	if err != nil {
		t.Fatal("RED: production no-effect WG retry remains pending without an independent WG verifier", err)
	}
}
