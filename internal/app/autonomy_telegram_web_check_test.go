package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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

func TestAutonomyReserveUsesLastCurrentlyAllowedOrigin(t *testing.T) {
	now := time.Unix(10000, 0)
	policy := autonomy.Policy{Protocols: []string{"vless"}, SourceIDs: []string{"one", "two"}}
	node := nodestore.Node{Protocol: "vless", Origins: []nodestore.Origin{
		{SourceID: "one", ReceivedAt: now, ExpiresAt: now.Add(time.Minute)},
		{SourceID: "two", ReceivedAt: now, ExpiresAt: now.Add(2 * time.Minute)},
		{SourceID: "unknown", ReceivedAt: now, ExpiresAt: now.Add(time.Hour)},
		{SourceID: "one", ReceivedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)},
	}}
	deadline := now.Add(2 * time.Minute)
	if got := allowedAutonomyNodeUntil(policy, node, now); !got.Equal(deadline) {
		t.Fatal("incorrect origin deadline", got)
	}
	if !allowedAutonomyNodeUntil(policy, node, deadline).IsZero() {
		t.Fatal("expired or unauthorized origin advertised")
	}
}

// Network I/O for the authorized feed uses an HTTPS fixture. Physical Home
// reads and the Xray engine are modeled. The worker, store, exclusion reader,
// feed queue, search, and service history follow their production paths.
func TestAutonomyHomeTelegramWebFeedCheckOnly(t *testing.T) {
	for _, scenario := range []string{"verified", "wrong-content", "excluded-domain", "revoked-during-check"} {
		t.Run(scenario, func(t *testing.T) {
			a, model := autonomyHomeCandidateFixture(t)
			a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
			a.Catalog = catalog.WithWebDefaults(catalog.Catalog{})
			svc, ok := a.autonomyService("telegram-web")
			if !ok {
				t.Fatal("missing stock service")
			}
			if err := a.Store.UpdateService(svc.ID, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			listScopeOperation(t, a, func(c context.Context) {
				epoch, err := a.Operations.ReviewControlEpoch(c, a.SelfUpdateFiles.ControlRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer epoch.Close()
				if scenario == "excluded-domain" {
					items := []config.ResourceMatch{{Kind: "suffix", Value: "telegram.org"}}
					if _, err := a.Store.UpdateResourceExclusions(c, a.Store.Get(), &items, nil); err != nil {
						t.Fatal(err)
					}
				}
				before := a.Store.Get()
				policy := config.CloneNetworkPolicy(before.NetworkPolicy)
				policy.Revision++
				ref := epoch.Reference()
				if _, err := a.Store.ApproveDefaultRouteConsent(c, before, policy, nil, ref.InstallationID, ref.Sequence); err != nil {
					t.Fatal(err)
				}
			})
			client := d10TLSFeedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/approved" {
					http.NotFound(w, r)
					return
				}
				fmt.Fprintln(w, "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls")
			}))
			root := filepath.Join(t.TempDir(), "feeds")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			feeds, err := providerfeed.OpenWithDependencies(a.Nodes, root, client, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			a.NodeFeeds = feeds
			source, err := feeds.Save(ctx, "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.test/approved", Limit: 1}, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			worker, cancel := context.WithCancel(ctx)
			a.StartNodeFeeds(worker)
			t.Cleanup(func() {
				cancel()
				join, done := context.WithTimeout(ctx, 10*time.Second)
				defer done()
				if err := errors.Join(a.WaitNodeFeeds(join), feeds.Close()); err != nil {
					t.Error(err)
				}
			})
			if err := a.loadAutonomy(ctx); err != nil {
				t.Fatal(err)
			}
			cfg := a.Store.Get()
			p := autonomy.Default()
			p.SetupComplete, p.Enabled, p.ManagedLANOnly, p.AllLAN, p.Revision = true, true, true, true, 1
			p.PreferredRoutes = []string{"xray"}
			p.SourceIDs = []string{source.SourceID}
			s := autonomy.Service{ID: svc.ID, Enabled: true, AllLAN: true, ManagedLANOnly: true, ExpectedRoute: "auto", Definition: autonomyDefinition(svc), DraftFingerprint: autonomyDraftFingerprint(cfg.Services[svc.ID])}
			a.autonomy.doc.Policy, a.autonomy.doc.Services[s.ID] = p, s
			if err := a.persistAutonomyLocked(ctx); err != nil {
				t.Fatal(err)
			}
			a.nodeReviews.options = func() []routecatalog.Option { return []routecatalog.Option{{ID: "xray", Installed: true}} }
			a.NodeHistoryWriteGuard = func(context.Context, int) error { return nil }
			checks := 0
			a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				if len(req.Service.Probes) != 1 || !req.Service.Probes[0].Required || !reflect.DeepEqual(req.Service, svc) || !slices.Equal(req.Service.Probes[0].Expect.BodyContains, []string{"Telegram Web"}) {
					t.Fatal("weakened web probe")
				}
				if scenario == "revoked-during-check" {
					a.autonomy.mu.Lock()
					a.autonomy.doc.Policy.Enabled = false
					a.autonomy.doc.Policy.Revision++
					err := a.persistAutonomyLocked(ctx)
					a.autonomy.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				body := "<html><title>Telegram Web</title></html>"
				if scenario == "wrong-content" {
					body = "<html>Welcome</html>"
				}
				observation := probecheck.Observation{RequestedURL: svc.ProbeURL, FinalURL: svc.ProbeURL, HTTPStatus: 200, ContentType: "text/html", Body: []byte(body)}
				assessment := probecheck.Evaluate(req.Service, probecheck.ServiceProbe(req.Service), observation)
				pass := assessment.Verdict == evidence.VerdictPass
				if pass != (scenario != "wrong-content") {
					t.Fatal("unexpected content assessment", assessment)
				}
				result := d10Result(req, "xray", pass)
				if !pass {
					result.Verdict, result.ErrorCode, result.HTTPStatus = assessment.Verdict, assessment.ErrorCode, 200
				}
				return result, nil
			})}
			withScope := telegramWebModelScope(a, model)
			run := func() autonomy.Runtime {
				a.autonomyRoundWithWebCheck(ctx, time.Now(), withScope)
				a.autonomy.mu.Lock()
				defer a.autonomy.mu.Unlock()
				return a.autonomy.doc.Runtime[s.ID].Clone()
			}
			r := run()
			if scenario == "excluded-domain" {
				if r.State != "excluded" || checks != 0 || len(r.Switches) != 0 || a.autonomy.refillState.State == "queued" {
					t.Fatal("excluded service probed or queued", r, checks)
				}
				return
			}
			if r.State != "searching" || a.autonomy.refillState.State != "queued" {
				t.Fatal("worker did not request first public page", r.State, r.Message, a.autonomy.refillState)
			}
			var id string
			end := time.Now().Add(8 * time.Second)
			for time.Now().Before(end) {
				snap, err := a.Nodes.Snapshot(ctx, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if len(snap.Nodes) == 1 {
					id = snap.Nodes[0].ID
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if id == "" {
				t.Fatal("worker did not import the permitted HTTPS source")
			}
			// The managed feed releases its own lease after importing. Drive
			// ordinary coordinator ticks until it can acquire its next turn.
			for checks == 0 && time.Now().Before(end) {
				r = run()
				if checks == 0 {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if checks != 1 || len(r.Switches) != 0 || !reflect.DeepEqual(a.Store.Get(), cfg) {
				t.Fatal("unexpected application or missing check", r.State, r.Message, checks)
			}
			snap, err := a.Nodes.Snapshot(ctx, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "revoked-during-check" {
				if r.State == homeServiceCheckedState || len(r.Reserves) != 0 || len(snap.Nodes[0].Health.History) != 0 {
					t.Fatal("revoked result persisted", r.State)
				}
				return
			}
			if scenario == "wrong-content" {
				if len(r.Reserves) != 0 || r.State == homeServiceCheckedState || len(snap.Nodes[0].Health.History) != 1 ||
					snap.Nodes[0].Health.History[0].ErrorCode != "body-predicate-mismatch" {
					t.Fatal("HTTP 200 with wrong content accepted", r.State, snap.Nodes[0].Health.History)
				}
				return
			}
			if r.State != homeServiceCheckedState || !slices.Equal(r.Reserves, []string{id}) || r.ReserveCheckedAt.IsZero() || !r.CheckedAt.IsZero() || len(snap.Nodes[0].Health.History) != 1 {
				t.Fatal("missing isolated service proof", r.State, r.Message, checks)
			}
			nextRound := func(due time.Time) autonomy.Runtime {
				a.autonomyRoundWithWebCheck(ctx, due, withScope)
				a.autonomy.mu.Lock()
				defer a.autonomy.mu.Unlock()
				return a.autonomy.doc.Runtime[s.ID].Clone()
			}
			due := time.Now().Add(24 * time.Hour)
			cached := nextRound(due)
			if cached.State != homeServiceCheckedState || !slices.Equal(cached.Reserves, r.Reserves) || !cached.ReserveCheckedAt.Equal(r.ReserveCheckedAt) || checks != 1 {
				t.Fatal("fresh reserve was lost or checked twice", cached.State, checks)
			}
			if !a.collectPanelAutonomy(ctx, "telegram-test", a.localPanelAutonomy) {
				t.Fatal("could not publish the verified reserve")
			}
			panelRuntime := func(at time.Time) autonomy.Runtime {
				t.Helper()
				var panel struct {
					Runtime map[string]autonomy.Runtime `json:"runtime"`
				}
				if err := json.Unmarshal(a.panelAutonomyAt(at).Data, &panel); err != nil {
					t.Fatal(err)
				}
				return panel.Runtime[s.ID]
			}
			if got := panelRuntime(time.Now()); !slices.Equal(got.Reserves, r.Reserves) {
				t.Fatal("fresh panel omitted a verified reserve", got.State)
			}
			listScopeOperation(t, a, func(c context.Context) {
				exclusions := []config.ResourceMatch{{Kind: "suffix", Value: "telegram.org"}}
				if _, err := a.Store.UpdateResourceExclusions(c, a.Store.Get(), &exclusions, nil); err != nil {
					t.Fatal(err)
				}
			})
			visible := a.autonomyView(time.Now())["runtime"].(map[string]autonomy.Runtime)[s.ID]
			for _, view := range []autonomy.Runtime{visible, panelRuntime(time.Now())} {
				if view.State != "pending" || len(view.Reserves) != 0 || !view.ReserveCheckedAt.IsZero() {
					t.Fatal("panel retained a reserve after the exclusion was saved", view.State)
				}
			}
			excluded := nextRound(due.Add(24 * time.Hour))
			if excluded.State != "excluded" || len(excluded.Reserves) != 0 || !excluded.ReserveCheckedAt.IsZero() || len(excluded.Switches) != 0 || checks != 1 {
				t.Fatal("exclusion retained a reserve, probed or applied", excluded.State, excluded.Reserves, checks)
			}
		})
	}
}

func telegramWebModelScope(a *App, model *nfqwsPacketModel) func(context.Context, config.Config, autonomy.Service, func(context.Context)) error {
	return func(c context.Context, cfg config.Config, s autonomy.Service, do func(context.Context)) error {
		base, err := newNFQWSPacketScopeBinding(c, a, func(ctx context.Context, b *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
			intent, err := b.intent(ctx)
			if err != nil {
				return nil, err
			}
			model.b, model.facts.Intent, model.facts.Control = b, intent, b.control.Reference()
			return model, nil
		})
		if err != nil {
			return err
		}
		b := &xrayHomeScopeBinding{base: base}
		b.self, base.homeOwner = b, b
		h := &autonomyXrayHomeRound{app: a, store: a.Store, original: c, spec: s, policy: config.CloneNetworkPolicy(cfg.NetworkPolicy), consent: config.CloneDefaultRouteConsent(cfg.DefaultRouteConsent), binding: b, webCheckOnly: true}
		h.self = h
		defer h.close()
		owned := context.WithValue(c, autonomyHomeScopeKey{}, h)
		if _, err := a.borrowAutonomyXrayHomeScope(owned); err == nil {
			return errors.New("domain diagnostic could lend routing authority")
		}
		return base.use(owned, func(held context.Context) error {
			return withAutonomyHomeScopeRead(held, b, func(marked context.Context) error { do(marked); return nil })
		})
	}
}
