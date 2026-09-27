package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func sourceRemovalFixture(t *testing.T) (*App, providerfeed.State, string) {
	t.Helper()
	a := autonomyAPIFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	feeds, err := providerfeed.Open(nil, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = feeds.Close() })
	a.NodeFeeds = feeds
	p := saveAutonomyFixturePolicy(t, a)
	if err := a.autonomyEnsureFeeds(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	s, err := feeds.Saved("feed-goida-extra")
	if err != nil {
		t.Fatal(err)
	}
	return a, s, root
}

func TestDeletingSubscriptionWithdrawsAutonomyAcrossRestart(t *testing.T) {
	for _, last := range []bool{false, true} {
		t.Run(map[bool]string{false: "other-transports-retained", true: "last-source-pauses"}[last], func(t *testing.T) {
			a, source, root := sourceRemovalFixture(t)
			if last {
				a.autonomy.mu.Lock()
				a.autonomy.doc.Policy.PreferredRoutes = nil
				err := a.persistAutonomyLocked(context.Background())
				a.autonomy.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			cfg, before := a.Store.Get(), a.autonomyPolicy()
			w := httptest.NewRecorder()
			a.nodeFeedAction(w, autonomyRequest("DELETE", "/api/v1/node-feeds/"+source.SourceID, map[string]any{"revision": source.Revision, "confirm": "DELETE_NODE_FEED"}))
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			p := a.autonomyPolicy()
			if slices.Contains(p.SourceIDs, source.SourceID) || p.Enabled == last || p.Revision != before.Revision+1 || !reflect.DeepEqual(a.Store.Get(), cfg) {
				t.Fatal("permission or active routes changed incorrectly")
			}
			if _, err := a.NodeFeeds.Saved(source.SourceID); !errors.Is(err, providerfeed.ErrNotFound) {
				t.Fatal("feed still present", err)
			}
			if err := a.NodeFeeds.Close(); err != nil {
				t.Fatal(err)
			}
			feeds, err := providerfeed.Open(nil, root)
			if err != nil {
				t.Fatal(err)
			}
			defer feeds.Close()
			restarted := &App{Store: a.Store, NodeFeeds: feeds}
			if err := restarted.loadAutonomy(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := restarted.autonomyEnsureFeeds(context.Background(), restarted.autonomyPolicy()); err != nil {
				t.Fatal(err)
			}
			if len(feeds.List()) != 0 {
				t.Fatal("worker resurrected removed subscription after restart")
			}
			// Another still-authorized origin remains eligible; retained node data
			// cannot itself restore the deleted source's consent.
			now := time.Now()
			node := nodestore.Node{Protocol: "vless", Origins: []nodestore.Origin{{SourceID: source.SourceID, ReceivedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
			if allowedAutonomyNode(p, node, now) {
				t.Fatal("withdrawn origin is still selectable")
			}
			p.SourceIDs = append(p.SourceIDs, "manual")
			node.Origins = append(node.Origins, nodestore.Origin{SourceID: "manual", ReceivedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
			if !allowedAutonomyNode(p, node, now) {
				t.Fatal("independent origin lost permission")
			}
		})
	}
}

func TestSourceDeletionCASAndConsentPersistenceFailClosed(t *testing.T) {
	for _, kind := range []string{"stale-feed", "replaced-autonomy", "busy"} {
		t.Run(kind, func(t *testing.T) {
			a, s, _ := sourceRemovalFixture(t)
			p := a.autonomyPolicy()
			revision := s.Revision
			want := http.StatusServiceUnavailable
			if kind == "stale-feed" {
				revision++
				want = 409
			}
			if kind == "replaced-autonomy" {
				if err := os.WriteFile(a.autonomy.path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "busy" {
				release, err := a.Operations.Enter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				want = 409
			}
			w := httptest.NewRecorder()
			a.operationMiddleware(http.HandlerFunc(a.nodeFeedAction)).ServeHTTP(w, autonomyRequest("DELETE", "/api/v1/node-feeds/"+s.SourceID, map[string]any{"revision": revision, "confirm": "DELETE_NODE_FEED"}))
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
			if _, err := a.NodeFeeds.Saved(s.SourceID); err != nil {
				t.Fatal("failed deletion removed feed")
			}
			if !reflect.DeepEqual(p, a.autonomyPolicy()) {
				t.Fatal("rejected deletion withdrew consent")
			}
		})
	}
}

func TestSourceDeletionInterruptedAfterWithdrawalKeepsRestriction(t *testing.T) {
	a, s, _ := sourceRemovalFixture(t)
	changed, _, err := a.withdrawAutonomySource(context.Background(), s.SourceID)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	restarted := &App{Store: a.Store, NodeFeeds: a.NodeFeeds}
	if err := restarted.loadAutonomy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(restarted.autonomyPolicy().SourceIDs, s.SourceID) {
		t.Fatal("interruption restored revoked permission")
	}
	w := httptest.NewRecorder()
	restarted.nodeFeedAction(w, autonomyRequest("DELETE", "/api/v1/node-feeds/"+s.SourceID, map[string]any{"revision": s.Revision, "confirm": "DELETE_NODE_FEED"}))
	if w.Code != 200 || len(a.NodeFeeds.List()) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
}
