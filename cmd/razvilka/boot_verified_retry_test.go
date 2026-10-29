package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// These are durable journal fixtures, not native runtime recovery evidence.
func verifiedBootRetryFixture(t *testing.T) (*config.Store, string, *dataplane.Manager, dataplane.Plan, dataplane.Plan, dataplane.Execution) {
	t.Helper()
	s, path, previous := bootReviewFixture(t)
	previous.PlanID = "dp-1111111111111111"
	previous.Digest = strings.Repeat("1", 64)
	previous.Adapters = []string{"nfqws2"}
	m := dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
	if err := m.Record(previous); err != nil {
		t.Fatal(err)
	}
	failed := previous
	failed.PlanID = "dp-2222222222222222"
	failed.Digest = strings.Repeat("2", 64)
	failed.State = "rolled-back"
	failed.Revision++
	if err := m.Record(failed); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	e := dataplane.Execution{PlanID: failed.PlanID, Digest: failed.Digest, State: "rolled-back", RollbackVerified: true, StartedAt: now, FinishedAt: now,
		Steps: []dataplane.ExecutionStep{{Adapter: "nfqws2", Phase: "retry-rollback", State: "passed", StartedAt: now, FinishedAt: now}, {Adapter: "nfqws2", Phase: "retry-verify-rollback", State: "passed", StartedAt: now, FinishedAt: now}}}
	writeVerifiedBootExecution(t, m, e, true)
	if err := s.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	return s, path, m, previous, failed, e
}

func writeVerifiedBootExecution(t *testing.T, m *dataplane.Manager, e dataplane.Execution, both bool) {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if both {
		root := filepath.Join(m.StateRoot, "transactions", e.PlanID)
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "execution.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifiedRetryBootReviewsSafeFlagOnlyAfterExactCertificate(t *testing.T) {
	s, path, m, p, _, _ := verifiedBootRetryFixture(t)
	before := s.Get()
	ordinary, err := bootRecoveryGuard(path, s)
	if err != nil || ordinary(p) == nil {
		t.Fatal("ordinary boot bypassed flag", err)
	}
	guard, err := bootRecoveryGuardForManager(path, s, m)
	if err != nil || guard(p) != nil {
		t.Fatal("exact verified retry could not review applied intent", err)
	}
	if !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("review changed flag/config")
	}
	// Only the real recovery completion path may retire the legacy flag.
	if err := settleRecoverySafeMode(s, dataplane.Recovery{State: "recovered"}, nil); err != nil || s.Get().SafeMode {
		t.Fatal(err)
	}
	if guard(p) == nil {
		t.Fatal("old review survived later configuration publication")
	}
}

func TestVerifiedRetryBootRejectsUnknownOrChangedCertificate(t *testing.T) {
	for _, mode := range []string{"unverified", "unfinished", "wrong-plan", "transaction-mismatch", "no-retry", "failed-tail", "truncated-tail", "wrong-adapter", "duplicate-adapter", "bad-plan-id", "missing-transaction", "previous-revision", "previous-subset", "previous-unready", "stopped", "suspended", "new-exclusion", "network-policy", "disk-stale", "disk-after", "journal-after", "previous-after"} {
		t.Run(mode, func(t *testing.T) {
			s, path, m, p, failed, e := verifiedBootRetryFixture(t)
			switch mode {
			case "unverified":
				e.RollbackVerified = false
				writeVerifiedBootExecution(t, m, e, true)
			case "unfinished":
				e.State = "rollback-failed"
				writeVerifiedBootExecution(t, m, e, true)
			case "wrong-plan":
				e.Digest = strings.Repeat("3", 64)
				writeVerifiedBootExecution(t, m, e, true)
			case "transaction-mismatch":
				e.Error = "changed"
				writeVerifiedBootExecution(t, m, e, false)
			case "no-retry":
				e.Steps[0].Phase = "rollback"
				e.Steps[1].Phase = "verify-rollback"
				writeVerifiedBootExecution(t, m, e, true)
			case "failed-tail":
				e.Steps[1].State = "failed"
				writeVerifiedBootExecution(t, m, e, true)
			case "truncated-tail":
				e.Steps = e.Steps[:1]
				writeVerifiedBootExecution(t, m, e, true)
			case "wrong-adapter":
				e.Steps[1].Adapter = "sing-box"
				writeVerifiedBootExecution(t, m, e, true)
			case "duplicate-adapter":
				failed.Adapters = []string{"nfqws2", "nfqws2"}
				if err := m.Record(failed); err != nil {
					t.Fatal(err)
				}
			case "bad-plan-id":
				failed.PlanID = "dp-invalid"
				if err := m.Record(failed); err != nil {
					t.Fatal(err)
				}
			case "missing-transaction":
				if err := os.Remove(filepath.Join(m.StateRoot, "transactions", failed.PlanID, "execution.json")); err != nil {
					t.Fatal(err)
				}
			case "previous-revision":
				p.Revision++
				if err := m.Record(p); err != nil {
					t.Fatal(err)
				}
				if err := m.Record(failed); err != nil {
					t.Fatal(err)
				}
			case "previous-subset":
				p.Routes = p.Routes[:1]
				if err := m.Record(p); err != nil {
					t.Fatal(err)
				}
				if err := m.Record(failed); err != nil {
					t.Fatal(err)
				}
			case "previous-unready":
				p.Ready = false
				if err := m.Record(p); err != nil {
					t.Fatal(err)
				}
				if err := m.Record(failed); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				if err := s.SetSafeMode(false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.CommitServiceRuntime(true, map[string]string{"youtube": "nfqws2", "discord": "nfqws2"}, s.Get().Revision); err != nil {
					t.Fatal(err)
				}
				if err := s.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "new-exclusion":
				v := []config.ResourceMatch{{Kind: "suffix", Value: "youtube.com"}}
				if _, err := s.UpdateResourceExclusions(context.Background(), s.Get(), &v, nil); err != nil {
					t.Fatal(err)
				}
			case "suspended", "network-policy":
				c := s.Get()
				if mode == "suspended" {
					c.ServiceControl.Stopped = true
					c.ServiceControl.SuspendedServices = map[string]config.ServiceState{"youtube": {Enabled: true, Route: "nfqws2"}}
					c.ServiceControl.SuspendedRoutes = map[string]string{"youtube": "nfqws2"}
				} else {
					c.NetworkPolicy = &config.NetworkPolicy{Schema: 1, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
				}
				raw, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				s, err = config.Load(path)
				if err != nil {
					t.Fatal(err)
				}
			case "disk-stale":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := s.Get()
			guard, err := bootRecoveryGuardForManager(path, s, m)
			if err == nil {
				switch mode {
				case "disk-after":
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
						t.Fatal(err)
					}
				case "journal-after":
					e.Error = "later publication"
					writeVerifiedBootExecution(t, m, e, true)
				case "previous-after":
					changed := p
					changed.Revision++
					if err := m.Record(changed); err != nil {
						t.Fatal(err)
					}
					if err := m.Record(failed); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err == nil && guard(p) == nil {
				t.Fatal("uncertain/stale/expanded authority admitted", mode)
			}
			if !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("refusal changed owner config")
			}
		})
	}
}
