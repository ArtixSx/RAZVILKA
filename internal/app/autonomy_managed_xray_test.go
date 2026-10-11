package app

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestAutonomyXrayProductionBorrowRefusesPhysicalModel(t *testing.T) {
	autonomyDeviceFixture(t, func(a *App, ctx context.Context, p autonomy.Policy, s autonomy.Service, service catalog.Service, model *listScopePhysicalModel, d *autonomyDeviceScope) {
		if a.autonomyResourceGuard(ctx, p, s, a.Store.Get(), service) != nil {
			t.Fatal("explicit selected-device model fixture is invalid")
		}
		if b, err := a.autonomyXrayScope(ctx); err == nil || b != nil || d.borrowUsed || d.borrowed {
			t.Fatal("a model callback/DTO entered production physical borrow", err)
		}
	})
}

// Actual Store/control/NodeStore/import/source and receipt APIs. Only physical
// acquisition, WAN and recorded node health use the named existing fixture
// models. No native runtime, forwarding, automatic fetch or path PASS claimed.
func autonomyXrayCandidateFixture(t *testing.T, use func(*listXraySourceFixture, context.Context, autonomy.Policy, autonomy.Service, string)) {
	t.Helper()
	f := newListXraySourceFixture(t, "") // Original A deliberately has no PASS.
	aID := f.nodeID
	input := "vless://123e4567-e89b-12d3-a456-426614174001@candidate.example:443?security=tls&sni=front.example"
	snapshot, err := f.a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, input, f.now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	cID := ""
	for _, n := range snapshot.Nodes {
		if n.ID != aID {
			cID = n.ID
		}
	}
	if cID == "" {
		t.Fatal("actual C node was not imported")
	}
	f.nodeID = cID
	f.record(t, "xray", "explicit-C-health-model", f.now)
	f.nodeID = aID
	listScopeOperation(t, f.a, func(ctx context.Context) {
		if err := f.a.loadAutonomy(ctx); err != nil {
			t.Fatal(err)
		}
		p := autonomy.Default()
		p.SetupComplete, p.Enabled, p.Revision = true, true, 1
		p.SourceIDs, p.Protocols = []string{"manual"}, []string{"vless"}
		p.DefaultSources = []string{"192.168.1.40/32"}
		service, known := f.a.autonomyService("listed")
		if !known {
			t.Fatal("actual frozen catalog missing")
		}
		state := f.a.Store.Get().Services[service.ID]
		s := autonomy.Service{ID: service.ID, Enabled: true, Sources: []string{"192.168.1.40/32"}, ExpectedRoute: state.Route,
			DraftFingerprint: autonomyDraftFingerprint(state), Definition: autonomyDefinition(service)}
		f.a.autonomy.mu.Lock()
		f.a.autonomy.doc.Policy, f.a.autonomy.doc.Services[service.ID] = p, s
		err := f.a.persistAutonomyLocked(ctx)
		f.a.autonomy.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		control, err := f.a.Operations.ReviewControlEpoch(ctx, f.a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		owned, closeScope, err := newAutonomyDeviceScope(ctx, f.a, f.a.Store.Get(), control.Current, f.physical.acquire)
		if err != nil {
			t.Fatal(err)
		}
		defer closeScope()
		use(f, owned, p, s, "xray:"+cID)
	})
}

func TestAutonomyXrayCandidatePlanningLeavesAUntilActualStoreReceipt(t *testing.T) {
	autonomyXrayCandidateFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string) {
		before := f.a.Store.Get()
		candidate, err := f.a.xrayAutonomyCandidate(ctx, p, s, before, f.physical.network, route)
		if err != nil {
			t.Fatal("actual candidate planning", err)
		}
		if !reflect.DeepEqual(f.a.Store.Get(), before) || candidate.planned.Services[s.ID].Route != route || candidate.planned.Revision != before.Revision ||
			!reflect.DeepEqual(candidate.planned.NetworkPolicy, before.NetworkPolicy) || !reflect.DeepEqual(candidate.planned.DefaultRouteConsent, before.DefaultRouteConsent) {
			t.Fatal("planning wrote intent or renewed approval")
		}
		source, err := f.a.reviewXrayListRuntimeSource(ctx, f.scope, s.ID, f.adapter, candidate)
		if err != nil {
			t.Fatal("actual C service/WAN source, with no original A PASS", err)
		}
		defer source.Close()
		prepared, err := source.prepare(ctx, true)
		if err != nil {
			t.Fatal("ordinary C proof/closed compiler", err)
		}
		defer prepared.close()
		lan := prepared.compilation.LAN()
		if lan == nil || len(lan.Ingress) != 1 || !slices.Equal(lan.Ingress[0].Sources, s.Sources) || !reflect.DeepEqual(f.a.Store.Get(), before) {
			t.Fatal("candidate broadened client sources or published before real CAS")
		}
		undo, receipt, err := f.a.Store.ApplyAutonomyRouteReviewedWithRollback(s.ID, route, s.Sources, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.acceptAutonomyCommitted(ctx, receipt); err != nil {
			t.Fatal("same actual Store receipt/original scope", err)
		}
		if !candidate.committed || source.expected.Revision != before.Revision+1 || selectedRoute(source.expected.Services[s.ID]) != route || source.Current(ctx) != nil {
			t.Fatal("candidate did not close the actual commit image")
		}
		if err := undo(); err != nil {
			t.Fatal("actual original undo", err)
		}
		if !reflect.DeepEqual(f.a.Store.Get(), before) || source.Current(ctx) == nil || !source.invalid {
			t.Fatal("restored A revived candidate C forward source")
		}
	})
}

func TestAutonomyXrayCandidateSourceClosesActualDrift(t *testing.T) {
	for _, change := range []string{"WAN", "enrollment", "node-generation", "Store"} {
		t.Run(change, func(t *testing.T) {
			autonomyXrayCandidateFixture(t, func(f *listXraySourceFixture, ctx context.Context, p autonomy.Policy, s autonomy.Service, route string) {
				candidate, err := f.a.xrayAutonomyCandidate(ctx, p, s, f.a.Store.Get(), f.physical.network, route)
				if err != nil {
					t.Fatal(err)
				}
				source, err := f.a.reviewXrayListRuntimeSource(ctx, f.scope, s.ID, f.adapter, candidate)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				switch change {
				case "WAN":
					f.physical.network = "wan-different"
				case "enrollment":
					f.a.autonomy.mu.Lock()
					f.a.autonomy.doc.Policy.Enabled = false
					f.a.autonomy.mu.Unlock()
				case "node-generation":
					_, err = f.a.Nodes.Import(ctx, nodestore.Source{ID: "other", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174002@third.example:443?security=tls", time.Now().UTC(), time.Hour, false)
					if err != nil {
						t.Fatal(err)
					}
				case "Store":
					state := f.a.Store.Get().Services[s.ID]
					state.Sources = []string{"192.168.1.41/32"}
					if err := f.a.Store.UpdateService(s.ID, state); err != nil {
						t.Fatal(err)
					}
				}
				if source.Current(ctx) == nil || !source.invalid {
					t.Fatal("changed authority remained a C forward source", change)
				}
			})
		})
	}
}

func TestAutonomyRuntimeOperationRetainsSameGateForOriginalPendingCleanup(t *testing.T) {
	a := &App{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owned, closeRound, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	borrowed, release, err := a.privateExclusiveOperation(owned)
	if err != nil || borrowed != owned {
		t.Fatal("runtime created a competing Gate admission", err)
	}
	cleanup, err := a.Operations.ReviewExclusiveCleanup(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	closeRound()
	a.Operations.FenceJournal()
	finite, end := context.WithTimeout(context.WithoutCancel(borrowed), time.Second)
	defer end()
	if err := cleanup.WithCurrent(finite, func() error { return nil }); err != nil {
		t.Fatal("round close lost original pending cleanup", err)
	}
	if _, next, err := a.privateExclusiveOperation(finite); err == nil {
		if next != nil {
			next()
		}
		t.Fatal("a fence admitted new forward permission", err)
	}
	release()
	if cleanup.WithCurrent(finite, func() error { t.Fatal("released owner revived"); return nil }) == nil {
		t.Fatal("released original cleanup remained current")
	}
	if !a.Operations.Snapshot().Fenced {
		t.Fatal("joined original cleanup cleared recovery fence")
	}
}

func TestAutonomyXrayStopCompletionRejectsUnissuedAndCopies(t *testing.T) {
	a := &App{}
	if a.hasOriginalPendingManagedXrayStop() || a.originalManagedXrayStopCompleted(nil) || a.originalManagedXrayStopCompleted(&managedXrayStopCompletion{}) {
		t.Fatal("raw unknown fence/DTO fabricated terminal Stop")
	}
	p := &managedXrayStopCompletion{app: a, committed: config.Config{Revision: 1}}
	p.self = p
	copy := *p
	if a.originalManagedXrayStopCompleted(&copy) {
		t.Fatal("copied receipt fabricated original terminal completion")
	}
}
