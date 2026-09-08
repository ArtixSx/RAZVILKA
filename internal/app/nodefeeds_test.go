package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func TestNodeFeedHandlersAreExplicitBoundedAndRedacted(t *testing.T) {
	a := &App{NodeFeeds: providerfeed.New(nil)}
	for _, body := range []string{
		`{"preset_id":"goida-vless"}`,
		`{"preset_id":"goida-vless","confirm":"SYNC_NODE_FEED","extra":"private-token"}`,
		`{"url":"https://example.org/private-token","confirm":"SYNC_NODE_FEED"} {}`,
		`{"url":"` + strings.Repeat("x", 9000) + `","confirm":"SYNC_NODE_FEED"}`,
	} {
		w := httptest.NewRecorder()
		a.nodeFeedSync(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-feeds/sync", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "private-token") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("invalid feed mutation was accepted or echoed")
		}
	}
	w := httptest.NewRecorder()
	a.nodeFeedSync(w, httptest.NewRequest(http.MethodGet, "/api/v1/node-feeds/sync", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("GET performed sync")
	}
	w = httptest.NewRecorder()
	a.nodeFeedList(w, httptest.NewRequest(http.MethodGet, "/api/v1/node-feeds", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scheduled":false`) {
		t.Fatal("ephemeral sync advertised background schedule")
	}
	a.NodeFeeds = nil
	w = httptest.NewRecorder()
	a.nodeFeedSync(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-feeds/sync", strings.NewReader(`{"preset_id":"goida-vless","confirm":"SYNC_NODE_FEED"}`)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("unavailable registry accepted sync")
	}
}

func TestSavedNodeFeedAPIKeepsURLsPrivateAndChecksRevisionWithoutFetching(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	feeds, err := providerfeed.Open(nil, root)
	if err != nil {
		t.Fatal(err)
	}
	defer feeds.Close()
	a := &App{NodeFeeds: feeds}
	body := `{"url":"https://feed.example.org/private-path-token?secret=query-token","name":"Подписка","enabled":true,"limit":128,"confirm":"SAVE_NODE_FEED"}`
	w := httptest.NewRecorder()
	a.nodeFeedList(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-feeds", strings.NewReader(body)))
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "private-path-token") || strings.Contains(w.Body.String(), "query-token") {
		t.Fatal("save API failed or leaked subscription")
	}
	var result struct {
		Source providerfeed.State `json:"source"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Source.Saved {
		t.Fatal("save response missing source")
	}
	for _, bad := range []string{`{"url":"https://example.org/a","url":"https://example.org/b","confirm":"SAVE_NODE_FEED"}`, `{"URL":"https://example.org/a","confirm":"SAVE_NODE_FEED"}`, `{"enabled":null,"confirm":"SAVE_NODE_FEED"}`} {
		w = httptest.NewRecorder()
		a.nodeFeedList(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-feeds", strings.NewReader(bad)))
		if w.Code != http.StatusBadRequest {
			t.Fatal("ambiguous feed JSON accepted")
		}
	}
	path := "/api/v1/node-feeds/" + result.Source.SourceID
	w = httptest.NewRecorder()
	a.nodeFeedAction(w, httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"enabled":false,"revision":999,"confirm":"UPDATE_NODE_FEED"}`)))
	if w.Code != http.StatusConflict {
		t.Fatal("outdated edit accepted")
	}
	w = httptest.NewRecorder()
	a.nodeFeedAction(w, httptest.NewRequest(http.MethodPut, path, strings.NewReader(fmt.Sprintf(`{"enabled":false,"revision":%d,"confirm":"UPDATE_NODE_FEED"}`, result.Source.Revision))))
	if w.Code != http.StatusOK {
		t.Fatal("pause API failed")
	}
	var paused struct {
		Source providerfeed.State `json:"source"`
	}
	json.Unmarshal(w.Body.Bytes(), &paused)
	w = httptest.NewRecorder()
	a.nodeFeedAction(w, httptest.NewRequest(http.MethodDelete, path, strings.NewReader(fmt.Sprintf(`{"revision":%d,"confirm":"DELETE_NODE_FEED"}`, paused.Source.Revision))))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"nodes_retained":true`) {
		t.Fatal("delete API lost retention boundary")
	}
	if _, err := feeds.Saved(result.Source.SourceID); err == nil {
		t.Fatal("subscription not deleted")
	}
	if _, err := feeds.ExportPrivateIfPresent(context.Background()); err != nil {
		t.Fatal("empty durable registry invalid after delete")
	}
}
