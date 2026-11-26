package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func nodeBrowseFixture(t *testing.T) (*App, string) {
	t.Helper()
	a := savedPanelFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	a.Nodes = store
	_, err = store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls&type=ws&sni=secret.example&path=%2Fprivate", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if !a.publishPanelSnapshot(context.Background(), strings.Repeat("a", 32), time.Now()) {
		t.Fatal("base instance missing")
	}
	return a, filepath.Join(root, "nodes.private.json")
}

func TestPanelNodeBrowseCapturesOnlySuccessfulAdmittedLiveRead(t *testing.T) {
	a, path := nodeBrowseFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.panelNodeBrowseAt(time.Now()).State != "empty" {
		t.Fatal("startup invented node read")
	}
	serve := func() int {
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, panelTestRequest("GET", "/api/v1/nodes"))
		return w.Code
	}
	release, _ := a.Operations.Exclusive(context.Background())
	if serve() != 409 || a.panelSnapshots.nodes.Load() != nil {
		t.Fatal("busy live request published")
	}
	release()
	if serve() != 200 || a.panelSnapshots.nodes.Load() == nil {
		t.Fatal("live read did not capture")
	}
	first := a.panelSnapshots.nodes.Load()
	var data map[string][]map[string]any
	if json.Unmarshal(first.Data, &data) != nil || len(data["nodes"]) != 1 {
		t.Fatal("missing nodes")
	}
	allowed := map[string]bool{"id": true, "name": true, "protocol": true, "transport": true}
	for key := range data["nodes"][0] {
		if !allowed[key] {
			t.Fatal("private/proof/action field", key)
		}
	}
	for _, secret := range []string{"private.example", "secret.example", "123e4567", "server_port", "health", "generation", "origins", "sources", "groups", "TLS", "vless://"} {
		if strings.Contains(string(first.Data), secret) {
			t.Fatal("leaked non-display field", secret)
		}
	}
	a.Nodes = nil
	if serve() != 200 || a.panelSnapshots.nodes.Load() != first {
		t.Fatal("unavailable store replaced last good capture")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("browse changed private file")
	}
	for _, tc := range []struct {
		age   time.Duration
		state string
		data  bool
	}{{0, "retained", true}, {time.Minute, "retained", true}, {15 * time.Minute, "expired", false}, {-2 * time.Second, "expired", false}} {
		got := a.panelNodeBrowseAt(first.Generated.Add(tc.age))
		if got.State != tc.state || (len(got.Data) > 0) != tc.data {
			t.Fatal("age contract", got)
		}
	}
}

func TestPanelNodeBrowseProjectionBoundsPreserveOriginal(t *testing.T) {
	a, _ := nodeBrowseFixture(t)
	now := time.Now()
	input := nodestore.Snapshot{Nodes: []nodestore.Node{{ID: "node-" + strings.Repeat("b", 64), Name: "Visible", Protocol: "VLESS", Transport: "ws", Host: "private", Health: nodestore.Health{Verdict: "PASS"}}}}
	if !a.capturePanelNodeBrowse(input, now) {
		t.Fatal("capture failed")
	}
	first := a.panelSnapshots.nodes.Load()
	original := bytes.Clone(first.Data)
	input.Nodes[0].Name = "changed"
	if !bytes.Equal(first.Data, original) {
		t.Fatal("slice alias")
	}
	for _, bad := range []nodestore.Snapshot{{Nodes: []nodestore.Node{{ID: "bad", Name: "Name"}}}, {Nodes: append(input.Nodes, input.Nodes...)}, {Nodes: []nodestore.Node{{ID: input.Nodes[0].ID, Name: strings.Repeat("x", 321)}}}, {Nodes: make([]nodestore.Node, 513)}} {
		if a.capturePanelNodeBrowse(bad, now.Add(time.Second)) || a.panelSnapshots.nodes.Load() != first {
			t.Fatal("invalid capture replaced last good")
		}
	}
	large := nodestore.Snapshot{}
	for i := 0; i < nodestore.MaxNodes; i++ {
		large.Nodes = append(large.Nodes, nodestore.Node{ID: fmt.Sprintf("node-%064x", i), Name: strings.Repeat("<", 64), Protocol: strings.Repeat("V", 32), Transport: strings.Repeat("w", 32)})
	}
	if a.capturePanelNodeBrowse(large, now.Add(time.Second)) || a.panelSnapshots.nodes.Load() != first {
		t.Fatal("escaped encoded bytes exceeded cap and replaced last good capture")
	}
	if a.capturePanelNodeBrowse(input, now.Add(-time.Second)) || a.panelSnapshots.nodes.Load() != first {
		t.Fatal("older receipt replaced newer")
	}
	if !a.capturePanelNodeBrowse(nodestore.Snapshot{}, now.Add(time.Second)) || !strings.Contains(string(a.panelSnapshots.nodes.Load().Data), `"nodes":[]`) {
		t.Fatal("genuine empty live list was not retained")
	}
}

func TestPanelNodeBrowseHTTPOnlyReadsMemoryAndKeepsAdmission(t *testing.T) {
	a, _ := nodeBrowseFixture(t)
	a.capturePanelNodeBrowse(nodestore.Snapshot{Nodes: []nodestore.Node{{ID: "node-" + strings.Repeat("c", 64), Name: "Display", Protocol: "VLESS"}}}, time.Now())
	image := bytes.Clone(a.panelSnapshots.nodes.Load().Data)
	// Closed store and absent settings prove the endpoint cannot go back to disk.
	_ = a.Nodes.Close()
	a.Store = nil
	release, _ := a.Operations.Exclusive(context.Background())
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.FenceJournal()
		}
		for _, method := range []string{"GET", "HEAD", "POST"} {
			for _, auth := range []bool{false, true} {
				r, _ := http.NewRequest(method, server.URL+panelNodeBrowsePath, nil)
				r.Header.Set("Content-Type", "application/json")
				if auth {
					r.Header.Set("Authorization", "Bearer "+panelTestToken)
				}
				response, err := server.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				want := 200
				if method == "POST" {
					want = 405
				}
				if !auth {
					want = 401
				}
				if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal(method, auth, response.StatusCode)
				}
				if method == "HEAD" && len(body) > 0 {
					t.Fatal("HEAD body")
				}
				if auth && method == "GET" {
					var got panelDeviceBrowseResponse
					if json.Unmarshal(body, &got) != nil || got.State != "retained" || !bytes.Equal(got.Data, image) {
						t.Fatal("not immutable memory image")
					}
				}
			}
		}
		for _, path := range []string{"/api/v1/nodes", panelNodeBrowsePath + "/", panelNodeBrowsePath + "/extra"} {
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, panelTestRequest("GET", path))
			want := 409
			if fenced {
				want = 503
			}
			if w.Code != want {
				t.Fatal("admission bypass", path, w.Code)
			}
		}
		if got := a.Operations.Snapshot(); !got.Exclusive || got.Active != 1 {
			t.Fatal("lost original owner")
		}
	}
	r := panelTestRequest("POST", panelNodeBrowsePath)
	r.Header.Set("Origin", "https://foreign.invalid")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	a.Security = nil
	w = httptest.NewRecorder()
	a.operationMiddleware(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", panelNodeBrowsePath, nil))
	if w.Code != 401 {
		t.Fatal("missing auth exposed metadata")
	}
}
