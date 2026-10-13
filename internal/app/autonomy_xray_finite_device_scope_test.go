package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Actual Gate, Store, control, source, compiler, node proof and CAS receipt.
// Only physical/WAN/recorded health I/O use the existing explicit models.
// The private loan helper tests lifetime composition; it does not mint the
// concrete production issuer or claim a native runtime/path PASS.
func autonomyFiniteXrayFixture(t *testing.T, use func(*listXraySourceFixture, context.Context, autonomy.Policy, autonomy.Service, string, *autonomyDeviceScope, *int)) {
	autonomyFiniteXrayFixtureWithSetup(t, nil, use)
}

func autonomyFiniteXrayFixtureWithSetup(t *testing.T, setup func(*listXraySourceFixture, context.Context), use func(*listXraySourceFixture, context.Context, autonomy.Policy, autonomy.Service, string, *autonomyDeviceScope, *int)) {
	t.Helper()
	autonomyXrayCandidateFixture(t, func(f *listXraySourceFixture, parent context.Context, p autonomy.Policy, s autonomy.Service, route string) {
		// Mask the legacy fixture's model-only carrier, keeping its actual Gate.
		ctx := context.WithValue(parent, autonomyDeviceScopeKey{}, nil)
		if setup != nil {
			setup(f, ctx)
		}
		service, known := f.a.autonomyService(s.ID)
		if !known {
			t.Fatal("actual catalog missing")
		}
		purpose := &autonomyXrayFinitePurpose{policy: p, spec: s, service: service}
		control, err := f.a.Operations.ReviewControlEpoch(ctx, f.a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		retainedReads := 0
		owned, close, err := newAutonomyXrayFiniteDeviceScope(ctx, f.a, f.a.Store.Get(), control.Current, purpose,
			func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
				verify, snapshot, close, err := f.physical.acquire(c, selection)
				if err != nil {
					return nil, nil, nil, nil, err
				}
				observe := func() physicalscope.FiniteIPv4PacketObservation {
					v := snapshot()
					return physicalscope.FiniteIPv4PacketObservation{ReviewID: v.ReviewID, Identity: v.Identity, Selection: v.Selection, Segments: v.Segments, Devices: v.Devices,
						UnresolvedRouter: []physicalscope.FiniteIPv4UnresolvedRouter{{Interface: "br0", IfIndex: 3, Address: "fe80::99", State: 32, Flags: 128, Type: 1}}}
				}
				retained := func(c context.Context) error {
					retainedReads++
					if _, finite := c.Deadline(); !finite || c.Err() != nil {
						return physicalscope.ErrUnknown
					}
					return f.physical.verifyErr
				}
				return verify, observe, retained, close, nil
			})
		if err != nil {
			t.Fatal("finite source-level fixture", err)
		}
		defer close()
		d := owned.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope)
		use(f, owned, p, s, route, d, &retainedReads)
	})
}

// Change only real approved intent before opening the new original round.
// The explicit physical model retains canonical native IDs and supplies both
// excluded bindings; the source selection callback canonicalizes their IDs.
func autonomyFiniteMembershipSetup(t *testing.T, alias, exclusions bool) func(*listXraySourceFixture, context.Context) {
	t.Helper()
	return func(f *listXraySourceFixture, ctx context.Context) {
		before := f.a.Store.Get()
		policy := config.CloneNetworkPolicy(before.NetworkPolicy)
		policy.Revision++
		if alias {
			policy.Clients.SegmentIDs = []string{"Home"}
		}
		if exclusions {
			policy.Clients.ExcludedDeviceIDs = []string{"excluded-z", "excluded-a"}
			f.physical.facts.Devices = append(f.physical.facts.Devices,
				physicalscope.Device{ID: "excluded-z", MAC: "02:00:00:00:00:02", IfIndex: 3, Interface: "br0", SegmentID: "Bridge0", Addresses: []string{"192.168.1.41"}},
				physicalscope.Device{ID: "excluded-a", MAC: "02:00:00:00:00:04", IfIndex: 3, Interface: "br0", SegmentID: "Bridge0", Addresses: []string{"192.168.1.42"}})
		}
		if _, err := f.a.Store.ApproveDefaultRouteConsent(ctx, before, policy, nil, before.DefaultRouteConsent.InstallationID, before.DefaultRouteConsent.Sequence); err != nil {
			t.Fatal("actual client scope approval", err)
		}
	}
}

func TestAutonomyFiniteXrayMembershipNativeNameAndExactExcludedSet(t *testing.T) {
	for _, kind := range []string{"native-name", "exclusion-order", "both"} {
		t.Run(kind, func(t *testing.T) {
			alias, exclusions := kind != "exclusion-order", kind != "native-name"
			autonomyFiniteXrayFixtureWithSetup(t, autonomyFiniteMembershipSetup(t, alias, exclusions), func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, d *autonomyDeviceScope, _ *int) {
				facts, policy, before := d.finite.observe(), config.CloneNetworkPolicy(d.policy), f.a.Store.Get()
				if facts.Segments[0].ID != "Bridge0" || facts.Devices[0].SegmentID != "Bridge0" || alias && facts.Selection.SegmentIDs[0] != "Home" {
					t.Fatal("model did not preserve original intent/canonical facts")
				}
				if exclusions && (!slices.Equal(policy.Clients.ExcludedDeviceIDs, []string{"excluded-z", "excluded-a"}) || !slices.Equal(facts.Selection.SelectedDevices.ExcludedDeviceIDs, []string{"excluded-a", "excluded-z"})) {
					t.Fatal("reordered exclusions not reproduced")
				}
				service, _ := f.a.autonomyService(s.ID)
				if err := f.a.autonomyResourceGuard(ctx, p, s, before, service); err != nil {
					t.Fatal("original finite membership refused", err)
				}
				candidate, err := f.a.xrayAutonomyCandidate(ctx, p, s, before, f.physical.network, route)
				if err != nil {
					t.Fatal(err)
				}
				full, b, err := f.a.borrowAutonomyXrayFiniteScope(ctx, d, nil)
				if err != nil || full != nil || b == nil {
					t.Fatal("same model round loan refused", err)
				}
				defer b.Close()
				r, err := f.a.reviewXrayListRuntimeSourceOwner(ctx, xrayRuntimeScope{finite: b}, s.ID, f.adapter, candidate)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				prepared, err := r.prepare(ctx, true)
				if err != nil {
					t.Fatal("original finite compilation refused", err)
				}
				defer prepared.close()
				lan := prepared.compilation.LAN()
				if len(lan.Ingress) != 1 || lan.Ingress[0].SegmentID != policy.Clients.SegmentIDs[0] || lan.Ingress[0].Interface != "br0" || !slices.Equal(lan.Ingress[0].Sources, s.Sources) || !slices.Equal(lan.Ingress[0].IncludedMACs, []string{"02:00:00:00:00:01"}) || !slices.Contains(lan.Ingress[0].ExcludedMACs, "02:00:00:00:00:FF") {
					t.Fatal("attachment or known negative changed")
				}
				if exclusions {
					for _, mac := range []string{"02:00:00:00:00:02", "02:00:00:00:00:04"} {
						if !slices.Contains(lan.Ingress[0].ExcludedMACs, mac) {
							t.Fatal("explicit negative lost")
						}
					}
				}
				if err := prepared.current(ctx); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(d.finite.facts, facts) || !reflect.DeepEqual(d.policy, policy) || !reflect.DeepEqual(f.a.Store.Get(), before) {
					t.Fatal("membership rewrote selection/facts/policy/Store")
				}
			})
		})
	}
}

func TestAutonomyFiniteXrayMembershipRefusesAliasAndExclusionConflicts(t *testing.T) {
	autonomyFiniteXrayFixtureWithSetup(t, autonomyFiniteMembershipSetup(t, true, true), func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, _ string, d *autonomyDeviceScope, _ *int) {
		original := d.finite.observe()
		for _, change := range []string{"conflicting-aliases", "unknown-alias", "empty-alias", "device-alias-not-canonical", "ifindex", "interface", "selection-alias-changed", "dropped-excluded", "added-excluded", "changed-excluded", "duplicate-observed", "duplicate-intent", "duplicates-both", "empty-excluded"} {
			t.Run(change, func(t *testing.T) {
				d.finite.facts = d.finite.observe()
				defer func() { d.finite.facts = original }()
				clients := config.CloneNetworkPolicy(d.policy).Clients
				projection := d.finite.facts.Selection.SelectedDevices
				switch change {
				case "conflicting-aliases":
					second := d.finite.facts.Segments[0]
					second.ID = "Bridge1"
					second.IfIndex++
					d.finite.facts.Segments = append(d.finite.facts.Segments, second)
				case "unknown-alias":
					d.finite.facts.Segments[0].NativeName = "Guest"
				case "empty-alias":
					clients.SegmentIDs = []string{""}
					d.finite.facts.Selection.SegmentIDs = []string{""}
					d.finite.facts.Segments[0].NativeName = ""
				case "device-alias-not-canonical":
					d.finite.facts.Devices[0].SegmentID = "Home"
				case "ifindex":
					d.finite.facts.Devices[0].IfIndex++
				case "interface":
					d.finite.facts.Devices[0].Interface = "foreign0"
				case "selection-alias-changed":
					d.finite.facts.Selection.SegmentIDs = []string{"Bridge0"}
				case "dropped-excluded":
					projection.ExcludedDeviceIDs = projection.ExcludedDeviceIDs[:1]
				case "added-excluded":
					projection.ExcludedDeviceIDs = append(projection.ExcludedDeviceIDs, "excluded-other")
				case "changed-excluded":
					projection.ExcludedDeviceIDs[0] = "excluded-other"
				case "duplicate-observed":
					projection.ExcludedDeviceIDs = []string{"excluded-a", "excluded-a"}
				case "duplicate-intent":
					clients.ExcludedDeviceIDs = []string{"excluded-a", "excluded-a"}
				case "duplicates-both":
					projection.ExcludedDeviceIDs = []string{"excluded-a", "excluded-a"}
					clients.ExcludedDeviceIDs = []string{"excluded-a", "excluded-a"}
				case "empty-excluded":
					projection.ExcludedDeviceIDs = []string{"", "excluded-z"}
					clients.ExcludedDeviceIDs = []string{"", "excluded-z"}
				}
				if ids, err := d.finite.members(s, clients); err == nil || len(ids) != 0 {
					t.Fatal("changed/ambiguous membership accepted", change)
				}
			})
		}
		d.finite.facts = original
		service, _ := f.a.autonomyService(s.ID)
		if err := f.a.autonomyResourceGuard(ctx, p, s, f.a.Store.Get(), service); err != nil {
			t.Fatal("detached proposed mismatch revoked original scope", err)
		}
	})
}

func TestAutonomyFiniteXrayPurposeSelectsStartupWithoutActiveExecution(t *testing.T) {
	autonomyFiniteXrayFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, d *autonomyDeviceScope, _ *int) {
		// Model only the private startup bookkeeping needed for dispatch. The
		// production startup/provider constructor is not exercised on Windows.
		startup := &managedListPolicyOwner{app: f.a, manager: f.a.Dataplane}
		startup.self = startup
		r := &ManagedXraySelectedTCPListRuntime{app: f.a, manager: f.a.Dataplane, policy: startup, adapter: f.adapter}
		r.self = r
		f.a.managedListPolicy, f.a.managedXraySelectedTCPList = startup, r
		cfg := f.a.Store.Get()
		if r.active != nil || len(cfg.AppliedServices) != 0 || f.a.autonomyXrayFinitePurpose(cfg, startup) == nil {
			t.Fatal("first finite candidate required an already active execution")
		}
		copy := &managedListPolicyOwner{self: startup, app: startup.app, manager: startup.manager}
		if f.a.autonomyXrayFinitePurpose(cfg, copy) != nil {
			t.Fatal("another startup owner adopted finite purpose")
		}
		for _, change := range []string{"runtime-copy", "second-service", "non-xray", "all-devices"} {
			t.Run(change, func(t *testing.T) {
				image := f.a.Store.Get()
				switch change {
				case "runtime-copy":
					copy := &ManagedXraySelectedTCPListRuntime{self: r, app: r.app, manager: r.manager, policy: r.policy}
					f.a.managedXraySelectedTCPList = copy
					defer func() { f.a.managedXraySelectedTCPList = r }()
				case "second-service":
					f.a.autonomy.doc.Services["other"] = autonomy.Service{ID: "other", Enabled: true}
					defer delete(f.a.autonomy.doc.Services, "other")
					image.Services["other"] = config.ServiceState{Enabled: true, Route: "direct"}
				case "non-xray":
					state := image.Services[s.ID]
					state.Route, state.Mode = "wireguard", "wireguard"
					image.Services[s.ID] = state
				case "all-devices":
					image.NetworkPolicy.Clients.Mode = "lan_except"
				}
				if f.a.autonomyXrayFinitePurpose(image, startup) != nil {
					t.Fatal("generic/full purpose selected finite producer", change)
				}
			})
		}
	})
}

func TestAutonomyFiniteXrayOrdinaryManualToAutoKeepsOldRetainedOwner(t *testing.T) {
	autonomyFiniteXrayFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, d *autonomyDeviceScope, _ *int) {
		mode := "manual"
		if err := f.a.Store.UpdateServiceControl(&mode, nil, f.a.Store.Get().Revision); err != nil {
			t.Fatal(err)
		}
		f.record(t, "xray", "explicit-manual-A-health-model", time.Now().UTC())
		b := modeledXrayFiniteScope(t, ctx, f)
		r := finiteXraySource(t, ctx, f, b, s.ID)
		prepared, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.close()
		input := (&DefaultRouteExecutor{app: f.a}).input(prepared.compilation, r.expected)
		plan := defaultRouteClonePlan(dataplane.Plan{Routes: input.Routes, LAN: prepared.compilation.LAN(), NetworkProfileID: input.NetworkProfileID})
		_, started, finished := xrayAssemblySourceCAS(t, r)
		if err := r.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		oldFacts, oldExpected := b.facts, b.expected
		r.cancel()
		undo, receipt, err := r.store.UpdateManualToAutoReviewed(ctx, r.expected.Revision)
		if err != nil {
			t.Fatal(err)
		}
		defer undo()
		if err := r.acceptServiceModeComparison(ctx, receipt, plan, nil, false); err != nil {
			t.Fatal("ordinary mode comparison lost old finite owner", err)
		}
		if err := receipt.Accept(ctx); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(b.expected, oldExpected) || !reflect.DeepEqual(b.facts, oldFacts) || r.ctx.Err() == nil || r.scope != nil || r.finiteScope != b {
			t.Fatal("mode writer revived or replaced old finite forward scope")
		}
		// This is a new ordinary round after the exact mode receipt. It gets
		// new original physics; cleanup of the old A retains its old issuer.
		control, err := f.a.Operations.ReviewControlEpoch(ctx, f.a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		fresh := context.WithValue(ctx, autonomyDeviceScopeKey{}, nil)
		cfg := f.a.Store.Get()
		acquires := 0
		owned, close, err := newAutonomyXrayFiniteDeviceScope(fresh, f.a, cfg, control.Current, d.finite.purpose,
			func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
				acquires++
				verify, snapshot, close, err := f.physical.acquire(c, selection)
				if err != nil {
					return nil, nil, nil, nil, err
				}
				observe := func() physicalscope.FiniteIPv4PacketObservation {
					v := snapshot()
					return physicalscope.FiniteIPv4PacketObservation{ReviewID: v.ReviewID, Identity: v.Identity, Selection: v.Selection, Segments: v.Segments, Devices: v.Devices}
				}
				return verify, observe, func(context.Context) error { return f.physical.verifyErr }, close, nil
			})
		if err != nil {
			t.Fatal("new ordinary AUTO round", err)
		}
		defer close()
		next := owned.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope)
		service, _ := f.a.autonomyService(s.ID)
		if acquires != 1 || next == d || next.finite == d.finite || next.finite == nil || !reflect.DeepEqual(next.facts, physicalscope.Snapshot{}) || f.a.autonomyResourceGuard(owned, p, s, cfg, service) != nil {
			t.Fatal("AUTO adopted old carrier/full data instead of its original round")
		}
		if err := b.cleanupScopeCheck(ctx, plan.LAN); err != nil || acquires != 1 || !reflect.DeepEqual(b.facts, oldFacts) {
			t.Fatal("old cleanup reopened physics after Manual to AUTO", err)
		}
	})
}

func TestAutonomyFiniteXrayOriginalRoundLoanCASAndRetainedCleanup(t *testing.T) {
	autonomyFiniteXrayFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, d *autonomyDeviceScope, retained *int) {
		before := f.a.Store.Get()
		if !reflect.DeepEqual(d.facts, physicalscope.Snapshot{}) || d.observer != nil || d.review != nil || d.snapshot != nil || len(d.finite.facts.UnresolvedRouter) != 1 {
			t.Fatal("finite round fabricated a full Review/Snapshot")
		}
		service, _ := f.a.autonomyService(s.ID)
		if err := f.a.autonomyResourceGuard(ctx, p, s, before, service); err != nil {
			t.Fatal("original finite resource observation", err)
		}
		if full, finite, err := f.a.autonomyXrayScopeOwner(ctx); err == nil || full != nil || finite != nil || d.borrowUsed {
			t.Fatal("model callbacks entered concrete production loan")
		}
		candidate, err := f.a.xrayAutonomyCandidate(ctx, p, s, before, f.physical.network, route)
		if err != nil {
			t.Fatal(err)
		}
		full, b, err := f.a.borrowAutonomyXrayFiniteScope(ctx, d, nil)
		if err != nil || full != nil || b == nil || !d.borrowUsed || !d.borrowed || !reflect.DeepEqual(b.facts, d.finite.facts) {
			t.Fatal("same original round was not loaned", err)
		}
		defer b.Close()
		if _, next, err := f.a.borrowAutonomyXrayFiniteScope(ctx, d, nil); err == nil || next != nil {
			t.Fatal("original principal loan reused")
		}
		r, err := f.a.reviewXrayListRuntimeSourceOwner(ctx, xrayRuntimeScope{finite: b}, s.ID, f.adapter, candidate)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		prepared, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.close()
		plan := prepared.compilation.LAN()
		if len(plan.Ingress) != 1 || !slices.Equal(plan.Ingress[0].Sources, s.Sources) || !slices.Contains(plan.Ingress[0].ExcludedMACs, "02:00:00:00:00:FF") || !reflect.DeepEqual(before, f.a.Store.Get()) {
			t.Fatal("loan widened compilation or changed A before CAS")
		}
		undo, receipt, err := f.a.Store.ApplyAutonomyRouteReviewedWithRollback(s.ID, route, s.Sources, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		defer undo()
		if err := r.acceptAutonomyCommitted(ctx, receipt); err != nil {
			t.Fatal("finite union lost actual Store commit", err)
		}
		if r.scope != nil || r.finiteScope != b || !reflect.DeepEqual(b.facts, d.finite.facts) || !reflect.DeepEqual(b.expected, f.a.Store.Get()) || r.Current(ctx) != nil {
			t.Fatal("receipt replaced original issuer")
		}
		cleanup, err := f.a.Operations.ReviewExclusiveCleanup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		closes := f.physical.closes
		if err := d.Close(); err != nil || f.physical.closes != closes {
			t.Fatal("round close retired the loaned principal", err)
		}
		if b.ScopeCheck(ctx, plan) == nil || f.a.autonomyResourceGuard(ctx, p, s, f.a.Store.Get(), service) == nil {
			t.Fatal("round close retained forward admission")
		}
		fresh, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := cleanup.WithCurrent(fresh, func() error { return b.cleanupScopeCheck(fresh, plan) }); err != nil || *retained == 0 {
			t.Fatal("original retained cleanup lost after round close", err)
		}
		wrong := dataplane.CloneLANPolicyRuntime(plan)
		wrong.Generation = "foreign"
		if b.cleanupScopeCheck(fresh, wrong) == nil {
			t.Fatal("retained physics adopted foreign plan")
		}
		f.physical.verifyErr = physicalscope.ErrUnknown
		if !errors.Is(b.cleanupScopeCheck(fresh, plan), physicalscope.ErrUnknown) {
			t.Fatal("physical revocation waived for cleanup")
		}
		if err := b.Close(); err != nil || f.physical.closes != closes+1 {
			t.Fatal("loan retirement did not join original close once", err)
		}
		if err := d.Close(); err != nil || f.physical.closes != closes+1 {
			t.Fatal("original principal closed twice", err)
		}
	})
}

func TestAutonomyFiniteXrayRejectsCopiesBothFullAndFabricatedIssuer(t *testing.T) {
	for _, change := range []string{"round-copy", "finite-copy", "both", "full-borrow", "fabricated-principal", "physical-revoked", "observation-drift", "widened-source", "wrong-service"} {
		t.Run(change, func(t *testing.T) {
			autonomyFiniteXrayFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, d *autonomyDeviceScope, _ *int) {
				service, _ := f.a.autonomyService(s.ID)
				switch change {
				case "round-copy":
					copy := &autonomyDeviceScope{self: d, app: d.app, store: d.store, original: d.original, finite: d.finite}
					ctx = context.WithValue(ctx, autonomyDeviceScopeKey{}, copy)
				case "finite-copy":
					copy := *d.finite
					d.finite = &copy
				case "both":
					d.verify, d.snapshot = func(context.Context) error { return nil }, f.physical.snapshot
				case "full-borrow":
					if b, err := f.a.autonomyXrayScope(ctx); err == nil || b != nil || d.borrowUsed {
						t.Fatal("finite data adopted by full borrower")
					}
					return
				case "fabricated-principal":
					d.finite.principal = &physicalscope.FiniteIPv4PacketPrincipal{}
					if full, finite, err := f.a.autonomyXrayScopeOwner(ctx); err == nil || full != nil || finite != nil || d.borrowUsed {
						t.Fatal("raw typed DTO adopted as concrete principal")
					}
					return
				case "physical-revoked":
					f.physical.verifyErr = physicalscope.ErrUnknown
				case "observation-drift":
					d.finite.facts.UnresolvedRouter[0].State = 1
				case "widened-source":
					s.Sources = []string{"192.168.1.0/24"}
					if _, err := d.finite.members(s, d.policy.Clients); err == nil {
						t.Fatal("finite membership adopted a broader source")
					}
				case "wrong-service":
					s.ID = "other"
				}
				if f.a.autonomyResourceGuard(ctx, p, s, f.a.Store.Get(), service) == nil {
					t.Fatal("changed finite authority accepted", change)
				}
				if change == "physical-revoked" || change == "observation-drift" {
					f.physical.verifyErr = nil
					d.finite.facts.UnresolvedRouter[0].State = 32
					if f.a.autonomyResourceGuard(ctx, p, s, f.a.Store.Get(), service) == nil || !d.invalid {
						t.Fatal("restored physical tuple revived round")
					}
				}
			})
		})
	}
}

func TestAutonomyFiniteXrayAcquireRefusesWiderIntentBeforePhysics(t *testing.T) {
	autonomyFiniteXrayFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, d *autonomyDeviceScope, _ *int) {
		for _, change := range []string{"all", "two-devices", "two-segments", "ipv6", "subnet", "non-xray", "shared-dns-purpose"} {
			t.Run(change, func(t *testing.T) {
				cfg := f.a.Store.Get()
				purpose := *d.finite.purpose
				purpose.spec.Sources = slices.Clone(purpose.spec.Sources)
				switch change {
				case "all":
					cfg.NetworkPolicy = config.CloneNetworkPolicy(cfg.NetworkPolicy)
					cfg.NetworkPolicy.Clients.Mode = "lan_except"
				case "two-devices":
					cfg.NetworkPolicy = config.CloneNetworkPolicy(cfg.NetworkPolicy)
					cfg.NetworkPolicy.Clients.DeviceIDs = []string{"included", "other"}
				case "two-segments":
					cfg.NetworkPolicy = config.CloneNetworkPolicy(cfg.NetworkPolicy)
					cfg.NetworkPolicy.Clients.SegmentIDs = []string{"Bridge0", "Bridge1"}
				case "ipv6":
					purpose.spec.Sources = []string{"fd00::40/128"}
				case "subnet":
					purpose.spec.Sources = []string{"192.168.1.0/24"}
				case "non-xray":
					state := cfg.Services[s.ID]
					state.Route, state.Mode = "wireguard", "wireguard"
					cfg.Services[s.ID] = state
				case "shared-dns-purpose":
					purpose.service.Domains = []string{"example.org"}
				}
				attempt := context.WithValue(ctx, autonomyDeviceScopeKey{}, nil)
				acquired := false
				owned, close, err := newAutonomyXrayFiniteDeviceScope(attempt, f.a, cfg, func(context.Context) error { return nil }, &purpose,
					func(context.Context, physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
						acquired = true
						return nil, nil, nil, nil, nil
					})
				if err == nil || owned != nil || close != nil || acquired {
					t.Fatal("broader intent reached finite acquisition", change)
				}
			})
		}
	})
}
