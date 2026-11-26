package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// Real HTTP writers, empty node library, managed feed and durable scheduler.
// External HTTPS results, the Xray transport and physical LAN observations
// are modeled. A verified service may supply a reserve but no LAN route.
func TestWizardConfirmedScopeStartsAutomaticSelection(t *testing.T) {
	for _, raced := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-home", true: "changed-exclusions"}[raced], func(t *testing.T) { wizardAutomaticSelection(t, raced) })
	}
}
func wizardAutomaticSelection(t *testing.T, raced bool) {
	fixture, approval := defaultConsentHTTPFixture(t)
	nodeRoot := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(nodeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer nodes.Close()
	a := &App{Store: fixture.Store, Nodes: nodes, Security: fixture.Security, SelfUpdateFiles: fixture.SelfUpdateFiles, Catalog: catalog.WithWebDefaults(catalog.NFQWS2Starter())}
	a.SelfUpdateFiles.Directory = filepath.Join(t.TempDir(), "self-update-files")
	a.FreshProfile = func(ctx context.Context) (string, error) { return "wan-0123456789ab", ctx.Err() }
	a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
	if err := a.ConfigureDefaultConsent(fixture.defaultConsent.configPath, nodeRoot); err != nil {
		t.Fatal(err)
	}
	defer a.CloseDefaultConsent()
	var fetched, checked atomic.Int32
	sourceID := "feed-igareck-black-vless"
	scopeRound := a.reconcileRound
	if !raced {
		_, _, model := nfqwsPacketFixture(t)
		model.facts.ExcludedMACs = nil
		approval["policy"].(*config.NetworkPolicy).Clients.SegmentIDs = []string{model.facts.Home.ID}
		client := d10TLSFeedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/approved" {
				http.NotFound(w, r)
				return
			}
			fetched.Add(1)
			fmt.Fprintln(w, "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls")
		}))
		feedRoot := filepath.Join(t.TempDir(), "feeds")
		if err := os.Mkdir(feedRoot, 0700); err != nil {
			t.Fatal(err)
		}
		feeds, err := providerfeed.OpenWithDependencies(nodes, feedRoot, client, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		a.NodeFeeds = feeds
		src, err := feeds.Save(t.Context(), "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.test/approved", Limit: 1}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		sourceID = src.SourceID
		feedCtx, stopFeeds := context.WithCancel(t.Context())
		a.StartNodeFeeds(feedCtx)
		defer func() {
			stopFeeds()
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if e := a.WaitNodeFeeds(c); e != nil {
				t.Error(e)
			}
			if e := feeds.Close(); e != nil {
				t.Error(e)
			}
		}()
		a.nodeReviews.options = func() []routecatalog.Option { return []routecatalog.Option{{ID: "xray", Installed: true}} }
		a.NodeHistoryWriteGuard = func(context.Context, int) error { return nil }
		a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
			checked.Add(1)
			obs := probecheck.Observation{RequestedURL: req.Service.ProbeURL, FinalURL: req.Service.ProbeURL, HTTPStatus: 200, ContentType: "text/html", Body: []byte("<html><title>Telegram Web</title></html>")}
			verdict := probecheck.Evaluate(req.Service, probecheck.ServiceProbe(req.Service), obs)
			ok := req.NodeID != "" && req.Service.ID == "telegram-web" && verdict.Verdict == evidence.VerdictPass
			return d10Result(req, "xray", ok), nil
		})}
		check := telegramWebModelScope(a, model)
		scopeRound = func(ctx context.Context, now time.Time) {
			a.reconcileRoundWithAutonomy(ctx, now, func(c context.Context, ts time.Time) { a.autonomyRoundWithWebCheck(c, ts, check) })
		}
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	call := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		status, data := componentHTTP(t, s, method, path, body, componentRecoveryToken, s.URL)
		if status != want {
			t.Fatalf("%s %s: %d %s", method, path, status, data)
		}
		var out map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err, string(data))
		}
		return out
	}
	const id = "telegram-web"
	wizard := initialScopeWizardBody(t, a, nil, []string{id})
	policy := wizard["policy"].(map[string]any)
	policy["source_ids"] = []string{"manual", sourceID}
	wizard["release_safe_mode"] = true
	wizard["expected_network_policy_revision"] = 0
	if snapshot, err := nodes.Snapshot(t.Context(), time.Now()); err != nil || len(snapshot.Nodes) != 0 {
		t.Fatal("initial catalog", snapshot, err)
	}
	if review := call("GET", networkPolicyReviewPath, nil, 200); review["scope_consent_current"] != false {
		t.Fatal(review)
	}
	// A missing scope cannot consume setup completion; the same wizard retries.
	if reply := call("PUT", "/api/v1/autonomy", wizard, 409); reply["code"] != "NETWORK_POLICY_REVIEW_CHANGED" {
		t.Fatal(reply)
	}
	approval["grants"] = []config.DefaultRouteGrant{}
	first := call("POST", networkPolicyReviewPath, approval, 200)
	if first["scope_consent_current"] != true {
		t.Fatal(first)
	}
	read := call("GET", networkPolicyReviewPath, nil, 200)
	wizard["expected_network_policy_revision"] = read["policy"].(map[string]any)["revision"]
	// A second tab confirms a newer scope after the first tab observed revision 1.
	if raced {
		approval["expected_revision"] = read["revision"]
		approval["expected_policy_revision"] = wizard["expected_network_policy_revision"]
		changed := approval["policy"].(*config.NetworkPolicy)
		changed.Clients.ExcludedDeviceIDs = []string{"mac-02-00-00-00-00-55"}
		second := call("POST", networkPolicyReviewPath, approval, 200)
		if reply := call("PUT", "/api/v1/autonomy", wizard, 409); reply["code"] != "NETWORK_POLICY_REVIEW_CHANGED" || a.autonomyPolicy().SetupComplete {
			t.Fatal("stale submission", reply)
		}
		wizard["expected_network_policy_revision"] = second["policy"].(map[string]any)["revision"]
	}
	// Simulate a scheduler turn already examining the old first-run state.
	a.reconciler.mu.Lock()
	a.reconciler.doc.Operations = []automationOperation{{Kind: "feeds", State: "running"}}
	a.reconciler.mu.Unlock()
	freshWizard := call("GET", "/api/v1/autonomy", nil, 200)
	wizard["starter_sha256"] = freshWizard["starter"].(map[string]any)["sha256"]
	if fetched.Load() != 0 || checked.Load() != 0 {
		t.Fatal("first-run activity preceded consent")
	}
	call("PUT", "/api/v1/autonomy", wizard, 200)
	a.reconciler.mu.Lock()
	latched := a.reconciler.autonomyWakePending
	a.reconciler.mu.Unlock()
	if !latched {
		t.Fatal("enrollment was lost during an older feed turn")
	}
	ctx, cancel := context.WithCancel(t.Context())
	a.startServiceReconciler(ctx, scopeRound)
	defer func() {
		cancel()
		wait, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := a.WaitServiceReconciler(wait); err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(35 * time.Second)
	var rt autonomy.Runtime
	for time.Now().Before(deadline) {
		a.autonomy.mu.Lock()
		rt = a.autonomy.doc.Runtime[id].Clone()
		a.autonomy.mu.Unlock()
		if (!raced && rt.State == homeServiceCheckedState) || (raced && rt.State == "paused") {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	cfg := a.Store.Get()
	if !cfg.Services[id].Enabled || rt.NextCheck.IsZero() || cfg.AppliedServices[id].Enabled || len(rt.Switches) != 0 || !config.CurrentDefaultRouteScopeConsent(cfg) {
		t.Fatalf("unexpected route or missing subsequent check: %+v", rt)
	}
	if raced {
		if rt.State != "paused" || !slices.Equal(cfg.NetworkPolicy.Clients.ExcludedDeviceIDs, []string{"mac-02-00-00-00-00-55"}) {
			t.Fatal("changed scope was lost", rt)
		}
	} else {
		snapshot, err := nodes.Snapshot(t.Context(), time.Now())
		if err != nil || fetched.Load() < 1 || checked.Load() != 1 || rt.State != homeServiceCheckedState || len(snapshot.Nodes) != 1 || !slices.Equal(rt.Reserves, []string{snapshot.Nodes[0].ID}) || len(cfg.NetworkPolicy.Clients.ExcludedDeviceIDs) != 0 {
			t.Fatalf("empty Home: fetched=%d, checked=%d, runtime=%+v, error=%v", fetched.Load(), checked.Load(), rt, err)
		}
	}
	t.Logf("automatic selection for %s: %s, retry scheduled: %v", id, rt.State, !rt.NextCheck.IsZero())
}

func TestWizardScopeRevisionZeroRequiresPreviouslyLimitedScope(t *testing.T) {
	for _, sources := range [][]string{nil, {"192.168.1.9/32"}} {
		a := autonomyAPIFixture(t)
		p := autonomy.Default()
		p.AllLAN = false
		p.DefaultSources = sources
		if err := a.loadAutonomy(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.autonomy.mu.Lock()
		a.autonomy.doc.Policy = p
		err := a.persistAutonomyLocked(t.Context())
		a.autonomy.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		body := initialScopeWizardBody(t, a, nil, nil)
		body["expected_network_policy_revision"] = uint64(0)
		if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
			t.Fatalf("saved limited scope refused: %d %s", w.Code, w.Body.String())
		}
		current := a.autonomyPolicy()
		if current.AllLAN || current.ManagedLANOnly || !slices.Equal(current.DefaultSources, sources) || a.Store.Get().NetworkPolicy != nil {
			t.Fatal("existing scope changed", current)
		}
	}
}
