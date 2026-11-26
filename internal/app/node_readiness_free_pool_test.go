package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func openFreePoolFeeds(t *testing.T, a *App) *providerfeed.Manager {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	feeds, err := providerfeed.Open(a.Nodes, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = feeds.Close() })
	a.NodeFeeds = feeds
	return feeds
}

type freePoolChecker struct {
	readinessEngineChecker
	installed bool
}

func (c *freePoolChecker) RuntimeInstalled() bool { return c.installed }

func TestNodeReadinessFreePoolWithoutUserServices(t *testing.T) {
	for _, scenario := range []string{"empty", "starter", "starter-disabled", "feed-disabled", "feed-not-selected", "vless-not-selected", "engine-not-selected", "paused-service", "missing-engine", "only-xray-installed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			a, _, _, checker, adapter, start := readinessFixture(t)
			feeds := openFreePoolFeeds(t, a)
			saved, err := feeds.Save(ctx, "", providerfeed.SaveRequest{
				Request: providerfeed.Request{PresetID: "igareck-black-vless"}, Enabled: scenario != "feed-disabled",
			})
			if err != nil {
				t.Fatal(err)
			}
			raw := "vless://123e4567-e89b-12d3-a456-426614174049@standby.example:443?security=tls"
			snapshot, err := a.Nodes.Import(ctx, nodestore.Source{ID: saved.SourceID, Kind: "community"}, raw, start, time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			publicID := ""
			for _, n := range snapshot.Nodes {
				if n.Origins[0].SourceID == saved.SourceID {
					publicID = n.ID
				}
			}
			if publicID == "" {
				t.Fatal("missing public candidate")
			}
			p := &a.autonomy.doc.Policy
			p.SourceIDs = []string{"manual", saved.SourceID}
			p.PreferredRoutes = []string{"sing-box"}
			a.autonomy.doc.Services = map[string]autonomy.Service{}
			var xray *freePoolChecker
			switch scenario {
			case "starter", "starter-disabled":
				a.Catalog = catalog.NFQWS2Starter()
				s := a.Catalog.Services[0]
				if err := a.Store.UpdateService(s.ID, config.ServiceState{Enabled: scenario == "starter", Route: "nfqws2"}); err != nil {
					t.Fatal(err)
				}
				a.autonomy.doc.Services[s.ID] = autonomy.Service{ID: s.ID, Enabled: true, ExpectedRoute: "nfqws2"}
			case "feed-not-selected":
				p.SourceIDs = []string{"manual"}
			case "vless-not-selected":
				p.Protocols = []string{"trojan"}
			case "engine-not-selected":
				p.PreferredRoutes = []string{"direct"}
			case "paused-service":
				a.autonomy.doc.Services["my-independent-site"] = autonomy.Service{ID: "my-independent-site", Enabled: false, ExpectedRoute: "auto"}
			case "missing-engine", "only-xray-installed":
				p.PreferredRoutes = []string{"sing-box", "xray"}
				xray = &freePoolChecker{readinessEngineChecker{engine: "xray"}, scenario == "only-xray-installed"}
				a.NodeCheckers = map[string]dataplane.NodeChecker{"sing-box": &freePoolChecker{readinessEngineChecker{engine: "sing-box"}, false}, "xray": xray}
			}
			before := a.Store.Get()
			a.nodeReadinessRound(ctx, start.Add(time.Minute))
			if scenario == "empty" || scenario == "starter" {
				if checker.count() != 1 || checker.last() != publicID || !readinessEntry(a, publicID).Ready {
					t.Fatalf("standby check did not select the public candidate: calls=%d state=%s", checker.count(), a.nodeReadinessSnapshot(start.Add(time.Minute)).State)
				}
			} else if scenario == "only-xray-installed" {
				if xray.count() != 1 || xray.last() != publicID || readinessEntry(a, publicID).Engine != "xray" {
					t.Fatal("standby pool missed the installed authorized Xray runtime")
				}
			} else if scenario == "missing-engine" {
				if a.nodeReadinessSnapshot(start.Add(time.Minute)).State != "waiting-engine" || xray.count() != 0 {
					t.Fatal("missing runtime should be reported without a negative node observation")
				}
			} else if checker.count() != 0 {
				t.Fatalf("unexpected check after %s", scenario)
			}
			if len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("standby pool changed routing")
			}
		})
	}
}
