package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type committedReviewAdapter struct {
	*fakeAdapter
	before           func(context.Context, Plan)
	effects, cleanup int
}

func (a *committedReviewAdapter) Reconcile(ctx context.Context, p Plan) error {
	if a.before != nil {
		a.before(ctx, p)
	}
	if err := CheckCommittedRecoveryReview(ctx, p); err != nil {
		return err
	}
	a.effects++
	return nil
}
func (a *committedReviewAdapter) Deactivate(ctx context.Context) error {
	if _, bound := ctx.Value(committedRecoveryReviewKey{}).(*committedRecoveryReview); bound {
		return errors.New("cleanup inherited startup grant")
	}
	a.cleanup++
	return nil
}

func committedReviewFixture(t *testing.T, mixed bool) (*Manager, *committedReviewAdapter, Plan) {
	t.Helper()
	m := New(t.TempDir())
	a := &committedReviewAdapter{fakeAdapter: &fakeAdapter{id: "nfqws2"}}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	p, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"youtube.com"}}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Unix(100, 0))
	if err != nil || !p.Ready {
		t.Fatal(err, p.Blockers)
	}
	if mixed {
		p.Routes = append(p.Routes, Route{ServiceID: "telegram", Selected: "sing-box:node-test", Resolved: "sing-box:node-test", CIDRs: []string{"203.0.113.0/24"}})
		p.Adapters = append(p.Adapters, "sing-box")
		p.NetworkProfileID = executionNetwork
		m.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
		if err := m.Register(&fakeAdapter{id: "sing-box"}); err != nil {
			t.Fatal(err)
		}
	}
	p.State = "committed"
	if err := m.Record(p); err != nil {
		t.Fatal(err)
	}
	return m, a, p
}

func TestCommittedRecoveryReviewRequiresActualManagerBinding(t *testing.T) {
	for _, generic := range []bool{false, true} {
		m, a, _ := committedReviewFixture(t, false)
		ctx := context.Background()
		if generic {
			ctx = WithReviewGuard(ctx, func(context.Context) error { return nil })
		}
		_, err := m.Recover(ctx)
		if err == nil || a.effects != 0 || a.cleanup != 1 {
			t.Fatal("unguarded boot acquired start authority or cleanup was gated", err, a.effects, a.cleanup)
		}
	}
}

func TestCommittedRecoveryReviewFullPlanNormalAndNetworkIndependent(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		m, a, p := committedReviewFixture(t, mixed)
		calls := 0
		ctx := WithRecoveryReview(context.Background(), func(actual Plan) error {
			calls++
			if actual.PlanID != p.PlanID || len(actual.Routes) != len(p.Routes) {
				return ErrReviewChanged
			}
			// A callback receives detached data, not writable authority over the plan.
			actual.Routes[0].Domains[0] = "mutated.example"
			return nil
		})
		a.before = func(c context.Context, actual Plan) {
			if actual.Routes[0].Domains[0] != "youtube.com" {
				t.Error("callback mutated retained plan")
			}
			if mixed {
				subset := actual
				subset.Routes = actual.Routes[:1]
				if CheckCommittedRecoveryReview(c, subset) == nil {
					t.Error("subset became full-plan intent")
				}
			}
		}
		r, err := m.Recover(ctx)
		if mixed && !errors.Is(err, ErrNetworkChanged) || !mixed && err != nil || a.effects != 1 || calls < 3 {
			t.Fatal("full-plan boot review not repeated", r, err, a.effects, calls)
		}
	}
}

func TestCommittedRecoveryReviewRechecksIntentAndJournalImmediatelyBeforeEffects(t *testing.T) {
	for _, drift := range []string{"intent", "plan", "cancel"} {
		t.Run(drift, func(t *testing.T) {
			m, a, p := committedReviewFixture(t, false)
			allowed := true
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := WithRecoveryReview(base, func(Plan) error {
				if !allowed {
					return ErrReviewChanged
				}
				return nil
			})
			a.before = func(context.Context, Plan) {
				switch drift {
				case "intent":
					allowed = false
				case "plan":
					p.Routes[0].Domains = []string{"changed.example"}
					if err := m.recordLocked(p); err != nil {
						t.Error(err)
					}
				case "cancel":
					cancel()
				}
			}
			_, err := m.Recover(ctx)
			if err == nil || a.effects != 0 {
				t.Fatal("stale intent admitted boot effects", err, a.effects)
			}
		})
	}
}

func TestCommittedRecoveryReviewNeverInterposesUnknownJournalCleanup(t *testing.T) {
	m, a, _ := committedReviewFixture(t, false)
	if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), []byte(`{"state":"applying"}`), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	r, err := m.Recover(WithRecoveryReview(context.Background(), func(Plan) error { calls++; return ErrReviewChanged }))
	if !errors.Is(err, ErrExecutionJournal) || r.State != "journal-recovery-required" || calls != 0 || a.effects != 0 {
		t.Fatal("current intent bypassed unknown journal fence", r, err, calls)
	}
}

func TestCommittedRecoveryReviewPreservesEstablishedManagedScopeWithoutLegacyGrant(t *testing.T) {
	m, _, p := committedReviewFixture(t, false)
	p.LAN = &LANPolicyRuntimePlan{}
	p.NetworkProfileID = executionNetwork
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	if err := m.Record(p); err != nil {
		t.Fatal(err)
	}
	legacy := &fakeAdapter{id: "nfqws2"}
	m.Adapters["nfqws2"] = legacy
	calls := 0
	ctx := WithRecoveryReview(context.Background(), func(Plan) error { calls++; return ErrReviewChanged })
	r, err := m.Recover(ctx)
	if err != nil || r.State != "recovered" || !legacy.recovered || calls != 0 {
		t.Fatal("legacy startup callback replaced existing managed-scope authority", r, err, calls)
	}
	bound, err := m.reviewedRecoveryContext(ctx, p)
	if err != nil || CheckCommittedRecoveryReview(bound, p) == nil {
		t.Fatal("managed-scope reconciliation acquired false legacy NFQ boot grant", err)
	}
}
