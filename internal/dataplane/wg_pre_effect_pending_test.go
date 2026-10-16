package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

// Private source/tool leaves only. Every read still consumes the original
// production command admission; its begin syscall and reply are models.
// There is no native child, kernel observation, handshake or mutation proof.
type wgPreEffectToolModel struct {
	review        string
	reads         int
	refuse        string
	linkPresent   bool
	kernelOwn     string
	routes, rules string
}

func (m *wgPreEffectToolModel) ReadWGKernelLinks(ctx context.Context, _ netidentity.Identity) ([]physicalscope.WGKernelLink, error) {
	if m.refuse != "" {
		return nil, errWGInactiveUnknown
	}
	links := []physicalscope.WGKernelLink{{Name: "lo", Index: 1}}
	if m.kernelOwn != "" {
		links = append(links, physicalscope.WGKernelLink{Name: m.kernelOwn, Index: 2, Kind: "wireguard"})
	}
	return links, ctx.Err()
}

func (m *wgPreEffectToolModel) SameWGToolSource(other WGCommandToolRunner) bool { return other == m }

func (m *wgPreEffectToolModel) CheckWG(ctx context.Context, _ netidentity.Identity) error {
	return ctx.Err()
}
func (m *wgPreEffectToolModel) RunWG(ctx context.Context, grant WGCommandAdmission, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	wan := strings.Contains(joined, "route get ")
	link := len(args) == 4 && args[0] == "link" && args[1] == "show" && args[2] == "dev"
	listLink := strings.Contains(joined, "link show") && !link
	listRule := strings.Contains(joined, "rule show")
	listRoute := strings.Contains(joined, "route show table")
	peer := joined == "show all public-key"
	if !wan && !link && !listLink && !listRule && !listRoute && !peer {
		return nil, errors.New("WG no-effect model refused a non-read command")
	}
	if err := grant.WithStart(ctx, name, args, m.review, func() error { return nil }); err != nil {
		return nil, err
	}
	m.reads++
	if m.refuse != "" {
		return nil, errors.New("modeled original source read unknown")
	}
	if link {
		if m.linkPresent {
			return nil, ctx.Err()
		}
		return nil, errors.New("modeled original link absence")
	}
	if listLink {
		return []byte(`[{"ifname":"lo"}]`), ctx.Err()
	}
	if listRoute {
		if m.routes != "" {
			return []byte(m.routes), ctx.Err()
		}
		return []byte("[]"), ctx.Err()
	}
	if listRule {
		if m.rules != "" {
			return []byte(m.rules), ctx.Err()
		}
		return []byte("0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"), ctx.Err()
	}
	if peer {
		return nil, ctx.Err()
	}
	return []byte(`[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`), ctx.Err()
}

// Actual production WG adapter, Manager scope/compensation, profile Store,
// original source/material/control and both retained authored execution FDs.
// NI/WAN/LAN/kernel/tool leaves are explicit models. In particular the LAN
// inventory model is not a WG consumer RollbackVerifier.
func wgPreEffectPendingFixture(t *testing.T, bindSources ...bool) (*Manager, *retainedWGExecution, context.Context, *operationgate.ExclusiveCleanupReview, *lanPolicyReceiptModel) {
	return wgPreEffectPendingWith(t, len(bindSources) > 0 && bindSources[0], nil)
}

func wgPreEffectPendingWith(t *testing.T, bindSources bool, beforeSnapshot func(*WARPWireGuardAdapter)) (*Manager, *retainedWGExecution, context.Context, *operationgate.ExclusiveCleanupReview, *lanPolicyReceiptModel) {
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
	identity.mode = LANPolicyManagedListMode
	// Distinct tool names preserve the production read-vs-mutation classifier;
	// this private runner implements the leaves and never executes these paths.
	tools := WGCommandTools{EngineID: "wireguard", WG: filepath.Join(base, "tools", "wg"), IP: filepath.Join(base, "tools", "ip"), IPTables: filepath.Join(base, "tools", "iptables"), IP6Tables: filepath.Join(base, "tools", "ip6tables"), ReviewSHA256: toolsModel.review, Identity: *current, Provider: provider, Runner: toolsModel}
	if err := a.BindWGCommandTools(tools); err != nil {
		t.Fatal(err)
	}
	b, lanModel, _ := lanReceiptBindingFixture(t)
	b.Runtime.Runner = &wgPreEffectLANModel{base: lanModel, tools: tools}
	b.Runtime.IP, b.Runtime.IPTables, b.Runtime.IP6Tables = tools.IP, tools.IPTables, tools.IP6Tables
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyManagedListMode, Binding: b, InventoryCheck: func(c context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
		if got != identity.value || lan != nil && !reflect.DeepEqual(lan, lanModel.plan) {
			return ErrBackendInventoryUnknown
		}
		return c.Err()
	}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range []Adapter{gate, a, NewAmneziaWGAdapter(configs, m.StateRoot)} {
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
	if bindSources {
		checks, err := m.bindNetworkPolicyChecks(gate, func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
			return networkPolicyInventoryTestImage(identity.value, nil), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = checks.Close() })
		sources := map[string]*WGInactivityRead{}
		for _, id := range []string{"wireguard", "amneziawg"} {
			readTools := tools
			readTools.EngineID = id
			if id == "amneziawg" {
				readTools.WG, readTools.AWG = "", ""
			}
			source, err := ReviewWGInactivityRead(ctx, t.Context(), m, control, readTools)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = source.Close() })
			sources[id] = source
		}
		if err := checks.BindManagedWGInactivitySources(ctx, sources); err != nil {
			t.Fatal(err)
		}
	}
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
	if beforeSnapshot != nil {
		beforeSnapshot(a)
	}
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
		if step.Adapter == "wireguard" && (step.Phase == "stage" || step.Phase == "activate") {
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
	if latest.State != "rollback-failed" || transaction.State != "rollback-failed" || latest.RollbackVerified || transaction.RollbackVerified || !m.HasPendingManagedWG() || o.scope.wgCleanupJoined {
		t.Fatal("expected exact no-effect retry predicate/refusal boundary", latest, transaction, err)
	}
	// The original RED2d8a8041 is resolved only with a genuine bound source.
	// An unbound adapter still cannot certify itself through the old predicate.
	if err == nil {
		t.Fatal("unbound production WG retry bypassed independent readback")
	}
}

type wgPreEffectLANModel struct {
	base  *lanPolicyReceiptModel
	tools WGCommandTools
}

func (m *wgPreEffectLANModel) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case m.tools.IP:
		name = "ip"
	case m.tools.IPTables:
		name = "iptables"
	case m.tools.IP6Tables:
		name = "ip6tables"
	}
	return m.base.Run(ctx, name, args...)
}

// Only OS process reading is modeled. The actual original source session,
// command ABI/admission, complete link/RPDB/table/receipt reader and all file,
// control, NI/tool bookends continue to execute, including both observations.
func wgPreEffectModelProcesses(o *retainedWGExecution, fail bool) {
	wgPreEffectObserveProcesses(o, func(c context.Context, _ []string) error {
		if fail {
			return errWGInactiveUnknown
		}
		return c.Err()
	})
}

func wgPreEffectObserveProcesses(o *retainedWGExecution, processes func(context.Context, []string) error) {
	r := o.scope.wgSnapshot
	r.observe = func(ctx context.Context) error {
		return r.source.WithCurrent(ctx, o.scope.wgOwner.material.cleanup, func(c context.Context) error {
			view := r.source.shape
			view.Runner, view.IP, view.IPTables, view.IP6Tables = r.source, r.source.tools.IP, r.source.tools.IPTables, r.source.tools.IP6Tables
			err := view.verifyRuntimeInactive(c, processes)
			return errors.Join(err, r.source.CurrentFiles(c))
		})
	}
}

func TestWGPreEffectPendingRefusesUnknownPriorAttemptAndSourceChanges(t *testing.T) {
	for _, kind := range []string{"process", "source", "source-closed", "checks-closed", "snapshot-bytes", "snapshot-inode", "root-replaced", "activation-marker", "stage-attempt", "activate-attempt", "prior-runtime", "prior-active", "native-attempt", "source-after-observe", "journal-replaced", "own-link", "candidate-link", "nonempty-table", "rpdb", "foreign-receipt", "copied-witness"} {
		t.Run(kind, func(t *testing.T) {
			var prepare func(*WARPWireGuardAdapter)
			if kind == "prior-runtime" {
				prepare = func(a *WARPWireGuardAdapter) {
					if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(a.RuntimeConfigPath, []byte("retained original runtime"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind == "prior-active" {
				prepare = func(a *WARPWireGuardAdapter) { a.wgCommandTools.Runner.(*wgPreEffectToolModel).linkPresent = true }
			}
			m, o, ctx, cleanup, _ := wgPreEffectPendingWith(t, true, prepare)
			wgPreEffectModelProcesses(o, false)
			r, s := o.scope.wgSnapshot, o.scope
			switch kind {
			case "own-link":
				r.source.tools.Runner.(*wgPreEffectToolModel).kernelOwn = s.wgOwner.adapter.interfaceName()
			case "candidate-link":
				r.source.tools.Runner.(*wgPreEffectToolModel).kernelOwn = s.wgOwner.adapter.interfaceName() + "-canary"
			case "nonempty-table":
				r.source.tools.Runner.(*wgPreEffectToolModel).routes = `[{"dst":"default","dev":"foreign0","table":206}]`
			case "rpdb":
				r.source.tools.Runner.(*wgPreEffectToolModel).rules = "11000: from all lookup 206\n"
			case "foreign-receipt":
				a := s.wgOwner.adapter
				if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(a.StateRoot, wgPolicyReferenceFile), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "copied-witness":
				s.wgSnapshot = &wgPreEffectSnapshot{self: r, owner: s.wgOwner}
				t.Cleanup(func() { s.wgSnapshot = r })
			case "process":
				wgPreEffectModelProcesses(o, true)
			case "source":
				r.source.tools.Runner.(*wgPreEffectToolModel).refuse = "unknown"
			case "source-closed":
				_ = r.source.Close()
			case "checks-closed":
				_ = r.checks.Close()
			case "snapshot-bytes":
				if err := os.WriteFile(filepath.Join(r.root, "snapshot.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "snapshot-inode":
				path := filepath.Join(r.root, "snapshot.json")
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, r.image, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path + ".original"); err != nil {
					t.Fatal(err)
				}
			case "root-replaced":
				if err := os.Rename(r.root, r.root+".original"); err != nil {
					t.Skip(err)
				}
				if err := os.Mkdir(r.root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(r.root, "snapshot.json"), r.image, 0600); err != nil {
					t.Fatal(err)
				}
			case "activation-marker":
				if err := os.WriteFile(filepath.Join(r.root, "wg-activation-started"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "stage-attempt", "activate-attempt":
				c, end, err := o.operation(ctx, cleanup, false)
				if err != nil {
					t.Fatal(err)
				}
				defer end()
				c, cancel := context.WithCancel(c)
				cancel()
				if kind == "stage-attempt" {
					if err := s.wgOwner.adapter.Stage(c, s.plan, r.root); err == nil {
						t.Fatal("cancelled Stage passed")
					}
				} else {
					if err := s.wgOwner.adapter.Activate(c, s.plan, r.root); err == nil {
						t.Fatal("cancelled Activate passed")
					}
				}
			case "native-attempt":
				s.wgOwner.mutationAttempted.Store(true)
				t.Cleanup(func() { s.wgOwner.mutationAttempted.Store(false) }) // Explicit model teardown, no native effects.
			case "source-after-observe":
				observe := r.observe
				r.observe = func(c context.Context) error {
					if err := observe(c); err != nil {
						return err
					}
					return r.source.Close()
				}
			case "journal-replaced":
				path := filepath.Join(m.StateRoot, "latest-execution.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.JoinPendingManagedWG(ctx, cleanup); err == nil || !m.HasPendingManagedWG() || s.wgCleanupJoined {
				t.Fatal("unknown/prior/effect released original WG owner", kind, err)
			}
		})
	}
}

func TestWGPreEffectLegacyLinkErrorNeedsNewIndependentCurrentProof(t *testing.T) {
	m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t, true)
	// The legacy Snapshot query returned an error, not proof of initial link
	// absence. Only a NEW complete original observer may establish current
	// inactivity; its unknown process inventory must keep the original fence.
	wgPreEffectModelProcesses(o, true)
	if err := m.JoinPendingManagedWG(ctx, cleanup); err == nil || !m.HasPendingManagedWG() {
		t.Fatal("legacy error became retrospective absence")
	}
	wgPreEffectModelProcesses(o, false)
	if err := m.JoinPendingManagedWG(ctx, cleanup); err != nil || m.HasPendingManagedWG() {
		t.Fatal("new independent current absence did not settle", err)
	}
}

func TestWGPreEffectRollbackAloneDoesNotVerifyOrAcceptPlanCopy(t *testing.T) {
	m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t, true)
	wgPreEffectModelProcesses(o, true)
	c, end, err := o.operation(ctx, cleanup, false)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	s, a := o.scope, o.scope.wgOwner.adapter
	if err := a.Rollback(c, s.plan, s.wgSnapshot.root); err != nil {
		t.Fatal("exact original no-op rollback failed", err)
	}
	if s.wgCleanupJoined || !m.HasPendingManagedWG() {
		t.Fatal("no-op rollback created independent completion")
	}
	for _, change := range []string{"digest", "cidr", "adapter"} {
		p := s.plan
		p.Adapters = append([]string(nil), p.Adapters...)
		p.Routes = append([]Route(nil), p.Routes...)
		switch change {
		case "digest":
			p.Digest = strings.Repeat("c", 64)
		case "cidr":
			p.Routes[0].CIDRs = []string{"8.8.8.0/24"}
		case "adapter":
			p.Adapters[1] = "amneziawg"
		}
		if err := a.Rollback(c, p, s.wgSnapshot.root); err == nil {
			t.Fatal("changed plan acquired original no-op rollback", change)
		}
	}
	if err := m.JoinPendingManagedWG(ctx, cleanup); err == nil || !m.HasPendingManagedWG() || s.wgCleanupJoined {
		t.Fatal("no-op rollback replaced unknown independent consumer readback")
	}
}

func TestWGPreEffectPendingFinalJournalFailureInvalidatesCycle(t *testing.T) {
	m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t, true)
	wgPreEffectModelProcesses(o, false)
	s := o.scope
	s.wgRecords.syncDirectory = func(root *ownedfs.Root) error {
		if s.execution.State == "rolled-back" {
			return errors.New("modeled final durability failure")
		}
		return syncDataplaneJournalDirectory(root)
	}
	if err := m.JoinPendingManagedWG(ctx, cleanup); err == nil || !m.HasPendingManagedWG() || s.wgCleanupJoined {
		t.Fatal("failed final journals retained completion", err)
	}
	s.wgRecords.syncDirectory = nil
	wgPreEffectModelProcesses(o, true)
	if err := m.JoinPendingManagedWG(ctx, cleanup); err == nil || !m.HasPendingManagedWG() || s.wgCleanupJoined {
		t.Fatal("previous completion replaced fresh consumer proof", err)
	}
	wgPreEffectModelProcesses(o, false)
	if err := m.JoinPendingManagedWG(ctx, cleanup); err != nil || m.HasPendingManagedWG() {
		t.Fatal("fresh original retry could not complete", err)
	}
}

func TestWGPreEffectPendingSlowReadCompletesAfterCallerCancellation(t *testing.T) {
	m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t, true)
	entered, leave := make(chan struct{}), make(chan struct{})
	var once sync.Once
	wgPreEffectObserveProcesses(o, func(c context.Context, _ []string) error { once.Do(func() { close(entered); <-leave }); return c.Err() })
	caller, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.JoinPendingManagedWG(caller, cleanup) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("original read did not enter", err)
	case <-ctx.Done():
		t.Fatal("original source stalled")
	}
	cancel()
	close(leave)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("admitted compensation inherited caller cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("bounded original compensation stalled")
	}
	if caller.Err() == nil || m.HasPendingManagedWG() || o.scope.open {
		t.Fatal("post-compensation bookkeeping did not finish")
	}
}

func TestWGPreEffectPendingOriginalReadbackCompletesWithoutMutationReceipt(t *testing.T) {
	m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t, true)
	wgPreEffectModelProcesses(o, false)
	before := o.scope.wgSnapshot.source.tools.Runner.(*wgPreEffectToolModel).reads
	if err := m.JoinPendingManagedWG(ctx, cleanup); err != nil {
		data, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
		var e Execution
		_ = json.Unmarshal(data, &e)
		for _, step := range e.Steps {
			if step.State == "failed" {
				t.Log(step.Adapter, step.Phase, step.Detail)
			}
		}
		t.Fatal("original no-effect independent WG readback", err)
	}
	if m.HasPendingManagedWG() || !o.scope.wgCleanupJoined || o.scope.open {
		t.Fatal("original compensation did not settle/close")
	}
	if after := o.scope.wgSnapshot.source.tools.Runner.(*wgPreEffectToolModel).reads; after-before < 20 {
		t.Fatal("full independent original readback skipped", after-before)
	}
	var e Execution
	data, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
	if err != nil || json.Unmarshal(data, &e) != nil || e.State != "rolled-back" || e.RollbackVerified {
		t.Fatal("no-effect cleanup forged mutation receipt", e.State, e.RollbackVerified, err)
	}
}
