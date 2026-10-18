package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func TestManualNodeImportCountryIsSafeAndDurable(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"nodes", "feeds"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	nodes, err := nodestore.Open(filepath.Join(root, "nodes"))
	if err != nil {
		t.Fatal(err)
	}
	defer nodes.Close()
	feeds, err := providerfeed.Open(nodes, filepath.Join(root, "feeds"))
	if err != nil {
		t.Fatal(err)
	}
	defer feeds.Close()
	a := &App{Nodes: nodes, NodeFeeds: feeds}
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@private-node.example:443?security=tls#" + url.PathEscape("🇳🇱 Нидерланды private-label-marker")
	body, _ := json.Marshal(map[string]any{"profile": uri, "confirm": "STORE_REMOTE_NODES"})
	rec := httptest.NewRecorder()
	a.nodeImport(rec, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/import", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var result struct {
		Accepted int  `json:"accepted_nodes"`
		Total    int  `json:"total_nodes"`
		Changed  bool `json:"working_routes_changed"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Accepted != 1 || result.Total != 1 || result.Changed {
		t.Fatal("country metadata changed import/route semantics")
	}
	snapshot, err := nodes.Snapshot(context.Background(), time.Now())
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("node missing", err)
	}
	id := snapshot.Nodes[0].ID
	if feeds.CountryMetadata()[id].Code != "NL" {
		t.Fatal("manual label lost allowlisted country")
	}
	for _, secret := range []string{"private-label-marker", "private-node.example", "123e4567"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("private import value leaked")
		}
	}
	if err := feeds.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := providerfeed.Open(nodes, filepath.Join(root, "feeds"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.CountryMetadata()[id].Code != "NL" {
		t.Fatal("restart lost country")
	}
}

func TestManualNodeImportCountryFailurePreservesSuccessfulImport(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"nodes", "feeds"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	nodes, err := nodestore.Open(filepath.Join(root, "nodes"))
	if err != nil {
		t.Fatal(err)
	}
	defer nodes.Close()
	feeds, err := providerfeed.Open(nodes, filepath.Join(root, "feeds"))
	if err != nil {
		t.Fatal(err)
	}
	defer feeds.Close()
	// Force the existing subscription CAS to reject an externally changed image.
	marker := []byte("external-image-marker")
	if err := os.WriteFile(filepath.Join(root, "feeds", providerfeed.FileName), marker, 0600); err != nil {
		t.Fatal(err)
	}
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@private-node.example:443?security=tls#" + url.PathEscape("🇳🇱 Нидерланды private-label-marker")
	body, _ := json.Marshal(map[string]any{"profile": uri, "confirm": "STORE_REMOTE_NODES"})
	rec := httptest.NewRecorder()
	(&App{Nodes: nodes, NodeFeeds: feeds}).nodeImport(rec, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/import", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Отметку страны сохранить не удалось") {
		t.Fatalf("partial import warning absent: status %d", rec.Code)
	}
	snapshot, err := nodes.Snapshot(context.Background(), time.Now())
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("metadata failure lost accepted node", err)
	}
	image, err := os.ReadFile(filepath.Join(root, "feeds", providerfeed.FileName))
	if err != nil || string(image) != string(marker) {
		t.Fatal("external image overwritten", err)
	}
	if len(feeds.CountryMetadata()) != 0 {
		t.Fatal("uncommitted country published")
	}
	for _, secret := range []string{"private-label-marker", "private-node.example", "123e4567", "external-image-marker"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("private error value leaked")
		}
	}
}
