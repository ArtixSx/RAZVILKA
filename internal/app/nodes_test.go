package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestNodeListIsSanitizedAndReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const privateURI = "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls&type=ws&sni=secret.example&path=%2Fprivate"
	if _, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, privateURI, time.Now(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	a := &App{Nodes: store}
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"selectable":0`) {
		t.Fatalf("node list: %d %s", w.Code, w.Body.String())
	}
	for _, private := range []string{"private.example", "secret.example", "123e4567", "/private", "secret-node-", "vless://"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("node list exposed private material")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "nodes.private.json")); err != nil {
		t.Fatal("read-only list removed node state")
	}
}

func TestNodeListUnavailableAndMethodBoundary(t *testing.T) {
	a := &App{}
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatal("missing store is not explained")
	}
	w = httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/nodes", strings.NewReader("private")))
	if w.Code != http.StatusMethodNotAllowed || strings.Contains(w.Body.String(), "private") {
		t.Fatal("node list accepted a mutation")
	}
}
