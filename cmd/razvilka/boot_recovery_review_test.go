package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func bootReviewFixture(t *testing.T) (*config.Store, string, dataplane.Plan) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"youtube", "discord"} {
		if err = s.UpdateService(id, config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	p := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-test", Digest: "digest", Revision: s.Get().AppliedRevision, State: "committed", Ready: true, Routes: []dataplane.Route{{ServiceID: "youtube", Selected: "nfqws2", Resolved: "nfqws2"}, {ServiceID: "discord", Selected: "nfqws2", Resolved: "nfqws2"}}}
	p.SiteExclusions, err = dataplane.LegacySiteExclusions(s.Get())
	if err != nil {
		t.Fatal(err)
	}
	return s, path, p
}

func TestBootRecoveryReviewMatchesAppliedNotDesiredOrAutopilot(t *testing.T) {
	s, path, p := bootReviewFixture(t)
	if err := s.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.50/32"}}); err != nil {
		t.Fatal(err)
	}
	manual := "manual"
	if err := s.UpdateServiceControl(&manual, nil, s.Get().Revision); err != nil {
		t.Fatal(err)
	}
	guard, err := bootRecoveryGuard(path, s)
	if err != nil || guard(p) != nil {
		t.Fatal("manual applied route/draft edits lost boot intent", err)
	}
	if len(p.Routes) != 2 {
		t.Fatal("full applied plan changed")
	}
}

func TestBootRecoveryReviewRefusesStoppedSafeModeMismatchAndNewScope(t *testing.T) {
	for _, drift := range []string{"stopped", "safe", "revision", "subset", "source", "route", "scope", "not-committed"} {
		t.Run(drift, func(t *testing.T) {
			s, path, p := bootReviewFixture(t)
			switch drift {
			case "stopped":
				if _, err := s.CommitServiceRuntime(true, map[string]string{"youtube": "nfqws2", "discord": "nfqws2"}, s.Get().Revision); err != nil {
					t.Fatal(err)
				}
			case "safe":
				if err := s.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "revision":
				p.Revision++
			case "subset":
				p.Routes = p.Routes[:1]
			case "source":
				p.Routes[0].Sources = []string{"192.168.1.50/32"}
			case "route":
				p.Routes[0].Selected = "direct"
			case "scope":
				manual := []config.ResourceMatch{{Kind: "suffix", Value: "youtube.com"}}
				if _, err := s.UpdateResourceExclusions(context.Background(), s.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
			case "not-committed":
				p.State = "reviewed"
			}
			guard, err := bootRecoveryGuard(path, s)
			if err != nil {
				t.Fatal(err)
			}
			if guard(p) == nil {
				t.Fatal("changed applied intent authorized boot", drift)
			}
		})
	}
}

func TestBootRecoveryReviewRetainsExactConfigurationBytes(t *testing.T) {
	s, path, p := bootReviewFixture(t)
	guard, err := bootRecoveryGuard(path, s)
	if err != nil || guard(p) != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if guard(p) == nil {
		t.Fatal("changed bytes reused original boot review")
	}
	if _, err := bootRecoveryGuard(filepath.Join(t.TempDir(), "missing"), s); err == nil {
		t.Fatal("missing config became boot grant")
	}
}

func TestBootRecoveryReviewCannotBindChangedDiskToOldStore(t *testing.T) {
	s, path, p := bootReviewFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The actual file changes after Store.Load, before the new review captures
	// its baseline. Exact later reads alone must not bless that stale Store.
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	guard, err := bootRecoveryGuard(path, s)
	if err != nil {
		t.Fatal(err)
	}
	if guard(p) == nil {
		t.Fatal("new baseline bytes were combined with stale cached applied settings")
	}
}
