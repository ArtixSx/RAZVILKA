package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestScopedDNSNetworkChangeReleasesRedirectsWithoutReplayingSettings(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.DNS.SetServiceDraft("web", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	a.FreshProfile = func(context.Context) (string, error) { return "wan-abcdef012345", nil }
	m.FreshProfile = a.FreshProfile
	r, err := m.Recover(context.Background())
	if !errors.Is(err, ErrNetworkChanged) || r.State != "network-stale" || r.Guarded || len(f.rules) != 0 || a.live != nil {
		t.Fatalf("stale DNS still intercepts clients: %+v %v", r, err)
	}
	if a.DNS.VerifyServiceSelection("web", "private") != nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
		t.Fatal("network invalidation changed configured intent")
	}
	in.NetworkProfileID = "wan-abcdef012345"
	in.Revision++
	next, _ := Build(in)
	if _, err := m.Apply(context.Background(), next, nil); err != nil {
		t.Fatal("fresh reviewed same profile cannot start", err)
	}
	if len(f.rules) != 2 || a.live == nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
		t.Fatal("fresh apply damaged pending DNS choice")
	}
}

func TestScopedDNSPrepareRecoveryUsesCleanBaselineAfterListenerLoss(t *testing.T) {
	for _, broken := range []string{"listener", "network", "failed-health", "journal", "changed-plan"} {
		t.Run(broken, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			old, _, _ := m.Committed()
			if err := a.DNS.SetServiceDraft("web", "unfiltered"); err != nil {
				t.Fatal(err)
			}
			if broken == "listener" {
				a.live.cancel()
				<-a.live.done
			}
			if broken == "network" {
				a.FreshProfile = func(context.Context) (string, error) { return "wan-abcdef012345", nil }
				m.FreshProfile = a.FreshProfile
				in.NetworkProfileID = "wan-abcdef012345"
			}
			if broken == "journal" {
				if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if broken == "changed-plan" {
				old.Revision++
			}
			err := m.PrepareDNSRecovery(context.Background(), old)
			if broken == "changed-plan" {
				if !errors.Is(err, ErrReviewChanged) || len(f.rules) != 2 || a.live == nil {
					t.Fatal("stale caller removed runtime", err)
				}
				return
			}
			if broken == "journal" {
				if !errors.Is(err, ErrExecutionJournal) || len(f.rules) != 0 || a.live != nil {
					t.Fatal("journal fence failed to clean DNS", err)
				}
				return
			}
			if err != nil || len(f.rules) != 0 || a.live != nil {
				t.Fatal("recovery not prepared", err)
			}
			if a.DNS.VerifyServiceSelection("web", "private") != nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
				t.Fatal("preparation replayed settings")
			}
			if broken == "failed-health" {
				a.HealthProbe = func(context.Context, *dnscontrol.ScopedDNSResolver, Plan) error {
					return errors.New("failed fresh probe")
				}
			}
			next, _ := Build(in)
			execution, err := m.Apply(context.Background(), next, nil)
			if broken == "failed-health" {
				if err == nil || execution.State != "rolled-back" || len(f.rules) != 0 || a.live != nil {
					t.Fatalf("failed recovery resurrected obsolete runtime: %+v %v", execution, err)
				}
			} else if err != nil || len(f.rules) != 2 || a.live == nil {
				t.Fatalf("recovery failed: %+v %v", execution, err)
			}
			if a.DNS.VerifyServiceSelection("web", "private") != nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
				t.Fatal("recovery consumed DNS draft")
			}
		})
	}
}

func TestScopedDNSRecoveryJournalFailureCleansOnlyOwnedRuntime(t *testing.T) {
	for _, corrupt := range []string{"latest-execution.json", "latest-committed-plan.json"} {
		t.Run(corrupt, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.StateRoot, corrupt), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := m.Recover(context.Background())
			if !errors.Is(err, ErrExecutionJournal) || r.State != "journal-recovery-required" || !r.Guarded || len(f.rules) != 0 || a.live != nil {
				t.Fatalf("orphan DNS not released: %+v %v", r, err)
			}
			if a.DNS.VerifyServiceSelection("web", "private") != nil {
				t.Fatal("unknown journal replayed settings")
			}
			if _, err := m.Apply(context.Background(), p, nil); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("cleanup reopened journal fence", err)
			}
		})
	}
}

func TestScopedDNSRecoveryForeignRulesRemainAndReportCleanupFailure(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	first := append([]string(nil), f.rules[0]...)
	f.rules[0][1] = "192.168.1.99/32"
	m.FreshProfile = func(context.Context) (string, error) { return "wan-abcdef012345", nil }
	r, err := m.Recover(context.Background())
	if err == nil || r.State != "safe-mode" || !r.Guarded || len(f.rules) != 2 || a.live == nil {
		t.Fatalf("foreign rule deleted or cleanup failure hidden: %+v %v", r, err)
	}
	f.rules[0] = first
}
