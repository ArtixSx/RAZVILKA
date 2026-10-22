package app

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func firstSearchSelectionFixture(now time.Time) ([]string, autonomyDocument, config.Config) {
	ids := []string{"a-check", "b-check", "c-check", "d-check", "e-check", "f-check", "telegram"}
	d := newAutonomyDocument()
	d.Policy.Enabled, d.Policy.SetupComplete = true, true
	cfg := config.Config{Services: map[string]config.ServiceState{}, AppliedServices: map[string]config.ServiceState{}}
	for i, id := range ids {
		d.Services[id] = autonomy.Service{ID: id, Enabled: true}
		d.Runtime[id] = autonomy.Runtime{State: "healthy", NextCheck: now.Add(time.Duration(i-10) * time.Minute)}
		cfg.Services[id] = config.ServiceState{Enabled: true, Route: "auto"}
	}
	d.Runtime["telegram"] = autonomy.Runtime{State: "searching", NextCheck: now.Add(-time.Second), Search: &autonomy.Traversal{Ordered: []string{"candidate-a", "candidate-b"}}}
	return ids, d, cfg
}

func copySelectionDocument(d autonomyDocument) autonomyDocument {
	copy := d
	copy.Runtime = map[string]autonomy.Runtime{}
	for id, r := range d.Runtime {
		copy.Runtime[id] = r.Clone()
	}
	return copy
}

func TestAutonomyFirstSearchGetsFasterDueSlotsWithoutStarvingOrdinaryChecks(t *testing.T) {
	start := time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC)
	run := func(priority bool) ([]time.Duration, map[string]bool) {
		ids, doc, cfg := firstSearchSelectionFixture(start)
		ordinaryNext := false
		searchSlots, ordinary := []time.Duration{}, map[string]bool{}
		for slot := 0; slot < 12; slot++ {
			now := start.Add(time.Duration(slot) * 30 * time.Second)
			before := copySelectionDocument(doc)
			id, usedPriority := selectAutonomyRound(ids, doc, cfg, now, !priority || ordinaryNext)
			if !reflect.DeepEqual(doc, before) {
				t.Fatal("selecting work changed cursor, cooldown, budget or due times")
			}
			if id == "" {
				continue
			}
			if ordinaryNext && usedPriority {
				t.Fatal("a first-search slot displaced the required ordinary turn")
			}
			ordinaryNext = usedPriority
			if id == "telegram" {
				searchSlots = append(searchSlots, now.Sub(start))
			} else {
				ordinary[id] = true
			}
			// Model the worker's existing completion scheduling. The selector
			// neither shortens this explicit 120-second interval nor changes
			// CandidatesPerRound; each search slot still checks at most two.
			r := doc.Runtime[id]
			r.NextCheck = now.Add(120 * time.Second)
			doc.Runtime[id] = r
		}
		return searchSlots, ordinary
	}
	baseline, _ := run(false)
	faster, ordinary := run(true)
	if len(baseline) != 1 || baseline[0] != 180*time.Second || !reflect.DeepEqual(faster, []time.Duration{0, 120 * time.Second, 240 * time.Second}) {
		t.Fatal("first search did not gain due slots under the seven-service serial schedule", baseline, faster)
	}
	if len(ordinary) != 6 {
		t.Fatal("routine service checks were starved", ordinary)
	}
}

func TestAutonomyFirstSearchPriorityPreservesPausesCooldownAndAppliedRecoveryOrder(t *testing.T) {
	now := time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC)
	for _, reason := range []string{"paused", "unconfirmed", "requires-review", "apply-refused", "future-due", "retry-cooldown", "candidate-cooldown", "halted", "exhausted", "applied", "removing"} {
		t.Run(reason, func(t *testing.T) {
			ids, doc, cfg := firstSearchSelectionFixture(now)
			r := doc.Runtime["telegram"]
			switch reason {
			case "paused", "unconfirmed", "requires-review":
				r.State = reason
			case "apply-refused":
				r.State, r.Search.Halted = reason, true
			case "future-due":
				r.NextCheck = now.Add(time.Second)
			case "retry-cooldown":
				r.Search.RetryAt = now.Add(time.Minute)
			case "candidate-cooldown":
				for _, id := range r.Search.Ordered {
					r.CandidateFailures = append(r.CandidateFailures, autonomy.CandidateFailure{NodeID: id, ObservedAt: now.Add(-time.Minute), Until: now.Add(time.Minute)})
				}
			case "halted":
				r.Search.Halted = true
			case "exhausted":
				r.Search.Cursor, r.Search.Exhausted = len(r.Search.Ordered), true
			case "applied":
				cfg.AppliedServices["telegram"] = config.ServiceState{Enabled: true, Route: "sing-box:node-old"}
			case "removing":
				s := doc.Services["telegram"]
				s.Removing = true
				doc.Services["telegram"] = s
			}
			doc.Runtime["telegram"] = r
			before := copySelectionDocument(doc)
			if id, priority := selectAutonomyRound(ids, doc, cfg, now, false); id != "a-check" || priority {
				t.Fatal("paused/cooling/applied work got a bonus slot", reason, id, priority)
			}
			// The same service is still eligible under the ordinary oldest-due
			// policy, including recovery of an assigned but failed VLESS path.
			if reason != "future-due" {
				r.NextCheck = now.Add(-time.Hour)
				doc.Runtime["telegram"] = r
				if id, priority := selectAutonomyRound(ids, doc, cfg, now, true); id != "telegram" || priority {
					t.Fatal("ordinary recovery/check scheduling changed", reason, id, priority)
				}
				doc.Runtime["telegram"] = before.Runtime["telegram"]
			}
			if !reflect.DeepEqual(doc, before) {
				t.Fatal("scheduling consumed or cleared a refusal/cooldown")
			}
		})
	}
	ids, doc, cfg := firstSearchSelectionFixture(now)
	r := doc.Runtime["telegram"]
	r.CandidateFailures = []autonomy.CandidateFailure{{NodeID: "candidate-a", ObservedAt: now.Add(-time.Minute), Until: now.Add(time.Minute)}}
	doc.Runtime["telegram"] = r
	if id, priority := selectAutonomyRound(ids, doc, cfg, now, false); id != "telegram" || !priority {
		t.Fatal("one cooling candidate blocked an available unconsumed peer", id, priority)
	}
	r.Search.Ordered = []string{"candidate-a"}
	r.CandidateFailures[0].Until = now
	doc.Runtime["telegram"] = r
	beforeExpiry := copySelectionDocument(doc)
	if id, priority := selectAutonomyRound(ids, doc, cfg, now, false); id != "telegram" || !priority || !reflect.DeepEqual(doc, beforeExpiry) {
		t.Fatal("an expired cooldown was extended or mutated by scheduling", id, priority)
	}
	for _, gate := range []string{"disabled", "safe-mode", "stopped", "manual"} {
		ids, doc, cfg := firstSearchSelectionFixture(now)
		switch gate {
		case "disabled":
			doc.Policy.Enabled = false
		case "safe-mode":
			cfg.SafeMode = true
		case "stopped":
			cfg.ServiceControl.Stopped = true
		case "manual":
			cfg.ServiceControl.Mode = "manual"
		}
		if id, _ := selectAutonomyRound(ids, doc, cfg, now, false); id != "" {
			t.Fatal("first-search priority bypassed the global gate", gate, id)
		}
	}
}

func TestAutonomyWorkerFirstSearchSlotStillUsesRealChecksAndApply(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), "telegram"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.autonomy.mu.Lock()
	r := a.autonomy.doc.Runtime["my-independent-site"]
	r.State, r.NextCheck = "searching", now.Add(-time.Second)
	r.Search = &autonomy.Traversal{Version: strings.Repeat("a", 64), Ordered: slices.Clone(ids)}
	a.autonomy.doc.Runtime["my-independent-site"] = r
	ordinary := a.autonomy.doc.Runtime["telegram"]
	ordinary.NextCheck = now.Add(-time.Hour)
	a.autonomy.doc.Runtime["telegram"] = ordinary
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.Service.ID)
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), now)
	a.autonomy.mu.Lock()
	ordinaryNext := a.autonomy.ordinaryAfterFirstSearch
	a.autonomy.mu.Unlock()
	if !reflect.DeepEqual(checked, []string{"my-independent-site"}) || autonomyTestState(a).State != "applied" || !slices.Contains(adapter.calls, "commit") || !ordinaryNext {
		t.Fatal("bonus slot skipped ordinary exact check/Apply or selected the older routine entry", checked, adapter.calls)
	}
	a.autonomy.mu.Lock()
	unchanged := a.autonomy.doc.Runtime["telegram"]
	a.autonomy.mu.Unlock()
	if !reflect.DeepEqual(unchanged, ordinary) {
		t.Fatal("first search edited the waiting service's explicit schedule")
	}
}
