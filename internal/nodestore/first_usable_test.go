package nodestore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func searchFixture(t *testing.T, count int, engine string) (*Store, []string, SearchRequest, SearchHooks) {
	t.Helper()
	s, _ := setup(t)
	var rows []string
	for i := range count {
		rows = append(rows, strings.Replace(good, "private-host.example", fmt.Sprintf("search-%d.example", i), 1))
	}
	snap, err := s.Import(context.Background(), manual, strings.Join(rows, "\n"), testTime, 2*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, n := range snap.Nodes {
		ids = append(ids, n.ID)
	}
	req := SearchRequest{Engine: engine, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", Ordered: ids, Limit: 4, AllowedSources: []string{"manual"}, Protocols: []string{"vless"}}
	now := testTime.Add(time.Minute)
	serial := 0
	hooks := SearchHooks{Guard: func(context.Context) error { return nil }, PersistCursor: func(context.Context, int) error { return nil }, Apply: func(context.Context, ResolvedRoute) error { return nil }, Now: func() time.Time { now = now.Add(time.Millisecond); return now }}
	hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
		serial++
		at := hooks.Now()
		probe := fmt.Sprintf("search-%d", serial)
		record := enginePass(id, engine, probe, at)
		if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
			return SearchCheck{}, err
		}
		return SearchCheck{Outcome: SearchUsable, ProbeID: probe, CheckedAt: at}, nil
	}
	return s, ids, req, hooks
}

func TestSearchFirstUsableAppliesImmediatelyAndKeepsEngine(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			s, ids, req, hooks := searchFixture(t, 4, engine)
			check := hooks.Check
			var events []string
			hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
				if id != ids[0] {
					t.Fatal("reserve checked before first Apply")
				}
				events = append(events, "check")
				return check(ctx, id)
			}
			hooks.PersistCursor = func(_ context.Context, cursor int) error {
				if cursor != 1 {
					t.Fatal("skipped unconsumed batch", cursor)
				}
				events = append(events, "persist")
				return nil
			}
			hooks.Apply = func(_ context.Context, r ResolvedRoute) error {
				events = append(events, "apply")
				if r.Route != engine+":"+ids[0] {
					t.Fatal("changed executor", r)
				}
				return nil
			}
			result, err := s.SearchFirstUsable(context.Background(), req, hooks)
			if err != nil || result.Checks != 1 || result.Examined != 1 || result.ApplyAttempts != 1 || result.Cursor != 1 || result.Applied.NodeID != ids[0] || !slices.Equal(events, []string{"check", "persist", "apply"}) {
				t.Fatal(result, events, err)
			}
		})
	}
}

func TestSearchBFailureRequiresVerifiedRollbackBeforeFreshCCheck(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			s, ids, req, hooks := searchFixture(t, 3, "xray")
			req.Current = ids[0]
			req.Cursor = 1
			// C's cached PASS cannot replace its check after rollback.
			old := enginePass(ids[2], "xray", "cached-C", testTime.Add(time.Second))
			if _, err := s.RecordCheck(context.Background(), ids[2], old, old.CheckedAt); err != nil {
				t.Fatal(err)
			}
			var events []string
			check := hooks.Check
			applyErr := errors.New("B health rejection")
			hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
				label := "B"
				if id == ids[2] {
					label = "C"
				}
				events = append(events, "check-"+label)
				return check(ctx, id)
			}
			hooks.Apply = func(_ context.Context, r ResolvedRoute) error {
				if r.NodeID == ids[1] {
					events = append(events, "apply-B")
					return applyErr
				}
				events = append(events, "apply-C")
				return nil
			}
			hooks.ContinueAfterRollback = func(_ context.Context, r ResolvedRoute, cause error) (bool, error) {
				if r.NodeID != ids[1] || !errors.Is(cause, applyErr) {
					t.Fatal("wrong candidate/cause")
				}
				events = append(events, "rollback-verified")
				return verified, nil
			}
			result, err := s.SearchFirstUsable(context.Background(), req, hooks)
			if verified {
				if err != nil || result.Applied.NodeID != ids[2] || result.Checks != 2 || !slices.Equal(result.Rejected, []string{ids[1]}) || !slices.Equal(events, []string{"check-B", "apply-B", "rollback-verified", "check-C", "apply-C"}) {
					t.Fatal(result, events, err)
				}
			} else if !errors.Is(err, applyErr) || result.Checks != 1 || result.ApplyAttempts != 1 || result.Applied.NodeID != "" || len(result.Rejected) != 0 {
				t.Fatal("unverified rollback advanced to C", result, events, err)
			}
		})
	}
}

func TestSearchCursorReachesCandidate33AcrossBoundedRounds(t *testing.T) {
	s, ids, req, hooks := searchFixture(t, 33, "sing-box")
	var visited []string
	check := hooks.Check
	cursor := 0
	hooks.PersistCursor = func(_ context.Context, next int) error { cursor = next; return nil }
	hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
		visited = append(visited, id)
		if id == ids[32] {
			return check(ctx, id)
		}
		return SearchCheck{Outcome: SearchUnsupported}, nil
	}
	for round := 0; round < 9; round++ {
		req.Cursor = cursor
		result, err := s.SearchFirstUsable(context.Background(), req, hooks)
		if err != nil || result.Checks > 4 {
			t.Fatal(result, err)
		}
		if round < 8 && result.Applied.NodeID != "" {
			t.Fatal("unexpected apply")
		}
		if round == 8 && result.Applied.NodeID != ids[32] {
			t.Fatal("candidate33 starved", result)
		}
	}
	if !slices.Equal(visited, ids) {
		t.Fatal("repeated prefix or skipped unconsumed candidates")
	}
	view, err := s.Snapshot(context.Background(), testTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range view.Nodes {
		if n.ID != ids[32] && len(n.Health.History) != 0 {
			t.Fatal("unsupported created record/penalty")
		}
	}
}

func TestSearchInvalidOrLocalEvidenceNeverAppliesOrPoisonsSources(t *testing.T) {
	for _, mode := range []string{"runtime", "cleanup", "busy", "cancel", "cached-pass", "wrong-engine", "wrong-service", "wrong-network", "direct-leak", "unrecorded", "inconclusive", "unsupported-with-probe", "persist-failed", "source-revoked", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			s, ids, req, hooks := searchFixture(t, 2, "xray")
			check := hooks.Check
			failure := errors.New("local/authority failure")
			applies := 0
			cursorWrites := 0
			hooks.Apply = func(context.Context, ResolvedRoute) error { applies++; return nil }
			hooks.PersistCursor = func(context.Context, int) error {
				cursorWrites++
				if mode == "persist-failed" {
					return failure
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
				if mode == "runtime" || mode == "cleanup" || mode == "busy" {
					return SearchCheck{}, failure
				}
				if mode == "cancel" {
					cancel()
					return SearchCheck{}, context.Canceled
				}
				if mode == "inconclusive" {
					return SearchCheck{}, nil
				}
				if mode == "unsupported-with-probe" {
					return SearchCheck{Outcome: SearchUnsupported, ProbeID: "fabricated"}, nil
				}
				if mode == "source-revoked" {
					hooks.Guard = func(context.Context) error { return failure }
					return SearchCheck{}, failure
				}
				if mode == "disabled" {
					if _, err := s.SetDisabled(ctx, id, true, hooks.Now()); err != nil {
						t.Fatal(err)
					}
					return SearchCheck{Outcome: SearchUsable, ProbeID: "missing", CheckedAt: hooks.Now()}, nil
				}
				if mode == "persist-failed" {
					return check(ctx, id)
				}
				at := hooks.Now()
				record := enginePass(id, "xray", "synthetic", at)
				switch mode {
				case "cached-pass":
					record.CheckedAt = testTime.Add(time.Second)
				case "wrong-engine":
					record.RoutePathID = "sing-box:" + id
				case "wrong-service":
					record.ServiceID = "youtube"
				case "wrong-network":
					record.NetworkProfile = "wan-abcdef123456"
				case "direct-leak":
					record.DirectLeak = true
				}
				if mode != "unrecorded" {
					if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
						t.Fatal(err)
					}
				}
				return SearchCheck{Outcome: SearchUsable, ProbeID: record.ProbeID, CheckedAt: record.CheckedAt}, nil
			}
			result, err := s.SearchFirstUsable(ctx, req, hooks)
			if err == nil || applies != 0 || result.ApplyAttempts != 0 || result.Checks != 1 {
				t.Fatal("uncertain result applied", result, err, applies)
			}
			if mode != "persist-failed" && cursorWrites != 0 {
				t.Fatal("uncertain candidate advanced", cursorWrites)
			}
			utility, err := s.SourceUtilityForEngine(context.Background(), "xray", []string{"manual"}, []string{"vless"}, req.ServiceID, req.NetworkProfile, hooks.Now())
			if err != nil {
				t.Fatal(err)
			}
			if utility["manual"] < 0 || len(result.Rejected) != 0 {
				t.Fatal("local failure poisoned source/candidate")
			}
			if mode == "runtime" || mode == "cleanup" || mode == "busy" || mode == "cancel" || mode == "inconclusive" || mode == "unsupported-with-probe" {
				snap, err := s.Snapshot(context.Background(), hooks.Now())
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range snap.Nodes {
					if len(n.Health.History) != 0 {
						t.Fatal("early local error persisted evidence")
					}
				}
			}
			_ = ids
		})
	}
}

func TestSearchRequiresFreshApprovedOriginAndSkipsCurrent(t *testing.T) {
	s, ids, req, hooks := searchFixture(t, 3, "xray")
	req.Current = ids[0]
	req.AllowedSources = []string{"unapproved"}
	checks := 0
	hooks.Check = func(context.Context, string) (SearchCheck, error) { checks++; return SearchCheck{}, nil }
	result, err := s.SearchFirstUsable(context.Background(), req, hooks)
	if err != nil || checks != 0 || result.Examined != 3 || result.Applied.NodeID != "" {
		t.Fatal("source allowlist widened", result, err)
	}
	req.AllowedSources = []string{"manual"}
	hooks.Now = func() time.Time { return testTime.Add(3 * time.Hour) }
	result, err = s.SearchFirstUsable(context.Background(), req, hooks)
	if err != nil || checks != 0 || result.Applied.NodeID != "" {
		t.Fatal("expired origin reused", result, err)
	}
}

func TestSearchDefiniteServiceFailureConsumesOnlyObservedCandidates(t *testing.T) {
	s, ids, req, hooks := searchFixture(t, 3, "sing-box")
	check := hooks.Check
	var visited []string
	var cursors []int
	hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
		visited = append(visited, id)
		if id != ids[0] {
			return check(ctx, id)
		}
		at := hooks.Now()
		record := enginePass(id, "sing-box", "definite-blocked", at)
		record.Verdict, record.State, record.ErrorCode = "BLOCKED", "unavailable", "service-rejected"
		if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
			t.Fatal(err)
		}
		return SearchCheck{Outcome: SearchDefiniteFailure, ProbeID: record.ProbeID, CheckedAt: at}, nil
	}
	hooks.PersistCursor = func(_ context.Context, next int) error { cursors = append(cursors, next); return nil }
	result, err := s.SearchFirstUsable(context.Background(), req, hooks)
	if err != nil || result.Checks != 2 || result.Cursor != 2 || result.ApplyAttempts != 1 || result.Applied.NodeID != ids[1] || !slices.Equal(visited, ids[:2]) || !slices.Equal(cursors, []int{1, 2}) {
		t.Fatal("definite failure skipped unobserved candidates", result, visited, cursors, err)
	}
}

func TestSearchRechecksAuthorityAndEligibilityAfterCursorPersistence(t *testing.T) {
	for _, mode := range []string{"consent", "disabled", "newer-exact-failure"} {
		t.Run(mode, func(t *testing.T) {
			s, ids, req, hooks := searchFixture(t, 2, "xray")
			authorized, applies, writes := true, 0, 0
			hooks.Guard = func(context.Context) error {
				if !authorized {
					return errors.New("consent changed during cursor persistence")
				}
				return nil
			}
			hooks.Apply = func(context.Context, ResolvedRoute) error { applies++; return nil }
			hooks.PersistCursor = func(ctx context.Context, next int) error {
				writes++
				if next != 1 {
					t.Fatal("advanced unconsumed batch")
				}
				switch mode {
				case "consent":
					authorized = false
				case "disabled":
					_, err := s.SetDisabled(ctx, ids[0], true, hooks.Now())
					return err
				case "newer-exact-failure":
					at := hooks.Now()
					record := enginePass(ids[0], "xray", "newer-blocked", at)
					record.Verdict, record.State = "BLOCKED", "unavailable"
					_, err := s.RecordCheck(ctx, ids[0], record, at)
					return err
				}
				return nil
			}
			result, err := s.SearchFirstUsable(context.Background(), req, hooks)
			if err == nil || applies != 0 || writes != 1 || result.Cursor != 1 || result.Checks != 1 || result.ApplyAttempts != 0 || len(result.Rejected) != 0 {
				t.Fatal("cursor I/O revoked guard/eligibility but still applied", result, applies, writes, err)
			}
		})
	}
}
