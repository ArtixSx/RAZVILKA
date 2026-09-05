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
	"github.com/ArtixSx/razvilka/internal/security"
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

func TestNodeMutationAndConfirmedReveal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const privateURI = "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls&sni=secret.example"
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, privateURI, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	a := &App{Nodes: store}
	handler := a.Handler(http.NotFoundHandler())

	request := httptest.NewRequest(http.MethodPatch, "/api/v1/nodes/"+id, strings.NewReader(`{"alias":"Резерв","disabled":true}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("multi-field mutation status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPatch, "/api/v1/nodes/"+id, strings.NewReader(`{"alias":"Резерв"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("alias status=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/reveal", strings.NewReader(`{"confirm":"NO"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired || strings.Contains(response.Body.String(), "123e4567") {
		t.Fatal("unconfirmed reveal exposed material")
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/reveal", strings.NewReader(`{"confirm":"REVEAL_NODE"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), "123e4567") || !strings.Contains(response.Body.String(), `"ui_clears_on_close":true`) {
		t.Fatal("confirmed reveal did not return bounded private material")
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/"+id, strings.NewReader(`{"confirm":"NO"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired {
		t.Fatal("unconfirmed delete was accepted")
	}
	request = httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/"+id, strings.NewReader(`{"confirm":"DELETE_NODE"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"working_routes_changed":false`) {
		t.Fatal("confirmed passive delete failed")
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil))
	if strings.Contains(list.Body.String(), "123e4567") || !strings.Contains(list.Body.String(), `"total":0`) {
		t.Fatal("deleted node remained in list or leaked")
	}
}

func TestNodeRevealRequiresAdministratorAuthentication(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const privateURI = "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls&sni=secret.example"
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, privateURI, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdefghijklmnopqrstuvwxyz-NODES"
	gate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	handler := (&App{Nodes: store, Security: gate}).Handler(http.NotFoundHandler())
	path := "http://router.local/api/v1/nodes/" + snapshot.Nodes[0].ID + "/reveal"

	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"confirm":"REVEAL_NODE"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://router.local")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "123e4567") {
		t.Fatal("unauthenticated reveal exposed private material")
	}

	request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"confirm":"REVEAL_NODE"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://router.local")
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "123e4567") {
		t.Fatalf("authenticated reveal status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNodeImportStoresAcceptedEntriesWithoutChangingRoutes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a := &App{Nodes: store}
	handler := a.Handler(http.NotFoundHandler())
	good := "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls&sni=secret.example"
	bad := "vless://123e4567-e89b-12d3-a456-426614174001@bad.example:443?security=tls&type=xhttp"

	request := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/import", strings.NewReader(`{"profile":"`+good+`\n`+bad+`","confirm":"STORE_REMOTE_NODES"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired {
		t.Fatalf("partial import without acceptance status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/nodes/import", strings.NewReader(`{"profile":"`+good+`\n`+bad+`","accept_partial":true,"confirm":"STORE_REMOTE_NODES"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"accepted_nodes":1`) || !strings.Contains(response.Body.String(), `"total_nodes":1`) || !strings.Contains(response.Body.String(), `"working_routes_changed":false`) {
		t.Fatalf("accepted import status=%d body=%s", response.Code, response.Body.String())
	}
	for _, secret := range []string{"123e4567", "private.example", "secret.example"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("node import response exposed private material")
		}
	}
	snapshot, err := store.Snapshot(context.Background(), time.Now())
	if err != nil || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].State != "quarantined" || snapshot.Nodes[0].Health.State != "not_checked" {
		t.Fatal("accepted node was not quarantined")
	}
}
