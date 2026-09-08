package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/security"
)

type fakeNodeChecker struct {
	result  dataplane.NodeCheckResult
	request dataplane.NodeCheckRequest
	err     error
	onCheck func()
}

func (f *fakeNodeChecker) Check(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	f.request = request
	if f.onCheck != nil {
		f.onCheck()
	}
	return f.result, f.err
}

func (*fakeNodeChecker) Recover(context.Context) error { return nil }

func stableNodeProfile(context.Context) (string, error) { return "wan-0123456789ab", nil }

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

func TestNodeGroupCRUDKeepsRuntimeAndMembersSafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	handler := (&App{Nodes: store}).Handler(http.NotFoundHandler())
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/api/v1/node-groups", strings.NewReader(`{"name":"Telegram резерв","mode":"fallback","node_ids":["`+id+`"],"preferred_node_id":"`+id+`","hold_down_seconds":1800,"confirm":"CREATE_NODE_GROUP"}`)))
	if create.Code != http.StatusCreated || !strings.Contains(create.Body.String(), `"working_routes_changed":false`) || strings.Contains(create.Body.String(), "private.example") {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		Group nodestore.NodeGroup `json:"group"`
	}
	if json.Unmarshal(create.Body.Bytes(), &created) != nil || created.Group.ID == "" {
		t.Fatal("created group ID is missing")
	}
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/"+id, strings.NewReader(`{"confirm":"DELETE_NODE"}`)))
	if blocked.Code != http.StatusConflict {
		t.Fatalf("group member deletion status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	update := httptest.NewRecorder()
	handler.ServeHTTP(update, httptest.NewRequest(http.MethodPut, "/api/v1/node-groups/"+created.Group.ID, strings.NewReader(`{"name":"Основной узел","mode":"manual","node_ids":["`+id+`"],"preferred_node_id":"`+id+`","hold_down_seconds":600,"confirm":"UPDATE_NODE_GROUP"}`)))
	if update.Code != http.StatusOK || !strings.Contains(update.Body.String(), `"mode":"manual"`) {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	remove := httptest.NewRecorder()
	handler.ServeHTTP(remove, httptest.NewRequest(http.MethodDelete, "/api/v1/node-groups/"+created.Group.ID, strings.NewReader(`{"confirm":"DELETE_NODE_GROUP"}`)))
	if remove.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", remove.Code, remove.Body.String())
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

func TestNodeExactCheckPersistsOnlySafeEvidence(t *testing.T) {
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
	now := time.Now().UTC()
	checker := &fakeNodeChecker{result: dataplane.NodeCheckResult{
		SchemaVersion: 1, ProbeID: "node-check-api", NodeID: id, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab",
		RoutePathID: "sing-box:" + id, StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(time.Hour),
		TestLevel: "service", Stage: "service", Verdict: evidence.VerdictPass, Available: true,
		EgressIP: "203.0.113.25", HTTPStatus: 204, LatencyMS: 1000, Message: "Узел и сервис подтверждены.",
	}}
	a := &App{Nodes: store, NodeChecker: checker, FreshProfile: stableNodeProfile, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Category: "messenger", Strategy: []string{"sing-box"}, ProbeURL: "https://telegram.org/"}}}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/check", strings.NewReader(`{"service_id":"telegram","confirm":"CHECK_NODE"}`))
	response := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"working_routes_changed":false`) || !strings.Contains(response.Body.String(), `"ok":true`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if checker.request.NodeID != id || checker.request.Service.ID != "telegram" || len(checker.request.Outbound) == 0 {
		t.Fatalf("checker did not receive the exact private node and catalog service: node=%q service=%q bytes=%d", checker.request.NodeID, checker.request.Service.ID, len(checker.request.Outbound))
	}
	listed, err := store.Snapshot(context.Background(), now)
	if err != nil || listed.Nodes[0].State != "available" || listed.Nodes[0].Health.EgressIP != "203.0.113.25" || listed.Nodes[0].Health.ServiceID != "telegram" {
		t.Fatalf("snapshot=%+v err=%v", listed, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "nodes.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The private document necessarily contains the original outbound once;
	// safe evidence must not duplicate its endpoint or SNI.
	if strings.Count(string(raw), "private.example") != 1 || strings.Count(string(raw), "secret.example") != 1 {
		t.Fatal("private endpoint was copied into persisted evidence")
	}
}

func TestNodeCheckRequiresCatalogProbeAndEnabledNode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	checker := &fakeNodeChecker{}
	handler := (&App{Nodes: store, NodeChecker: checker, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "manual", Name: "Manual", Category: "other", Strategy: []string{"sing-box"}}}}}).Handler(http.NotFoundHandler())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/check", strings.NewReader(`{"service_id":"manual","confirm":"CHECK_NODE"}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("probe-less service status=%d", response.Code)
	}
	if _, err := store.SetDisabled(context.Background(), id, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	handler = (&App{Nodes: store, NodeChecker: checker, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Category: "messenger", Strategy: []string{"sing-box"}, ProbeURL: "https://telegram.org/"}}}}).Handler(http.NotFoundHandler())
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/check", strings.NewReader(`{"service_id":"telegram","confirm":"CHECK_NODE"}`)))
	if response.Code != http.StatusConflict || checker.request.NodeID != "" {
		t.Fatalf("disabled node status=%d request=%+v", response.Code, checker.request)
	}
}

func TestNodeCheckDoesNotPersistProofAcrossNetworkChange(t *testing.T) {
	for _, scenario := range []string{"initial-unknown", "initial-empty", "changed", "became-unknown", "observation-error"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "nodes")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := nodestore.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Now().UTC()
			snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls", now, time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			id := snapshot.Nodes[0].ID
			profile := "wan-0123456789ab"
			var observationErr error
			if scenario == "initial-unknown" {
				profile = "network-unknown"
			} else if scenario == "initial-empty" {
				profile = ""
			}
			checker := &fakeNodeChecker{result: dataplane.NodeCheckResult{
				SchemaVersion: 1, ProbeID: "node-check-network", NodeID: id, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
				StartedAt: now, FinishedAt: now, ExpiresAt: now.Add(time.Hour), TestLevel: "service", Stage: "service", Verdict: evidence.VerdictPass, Available: true, Message: "Подтверждено.",
			}}
			checker.onCheck = func() {
				switch scenario {
				case "changed":
					profile = "wan-ffffffffffff"
				case "became-unknown":
					profile = "network-unknown"
				case "observation-error":
					observationErr = errors.New("private WAN details must not escape")
				}
			}
			a := &App{Nodes: store, NodeChecker: checker, FreshProfile: func(context.Context) (string, error) { return profile, observationErr }, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Category: "messenger", Strategy: []string{"sing-box"}, ProbeURL: "https://telegram.org/"}}}}
			response := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/check", strings.NewReader(`{"service_id":"telegram","confirm":"CHECK_NODE"}`)))
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "NODE_NETWORK_CHANGED") || strings.Contains(response.Body.String(), "private WAN") {
				t.Fatalf("unsafe network response: status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.HasPrefix(scenario, "initial-") && checker.request.NodeID != "" {
				t.Fatal("unknown initial network started a node check")
			}
			after, err := store.Snapshot(context.Background(), time.Now())
			if err != nil || after.Generation != snapshot.Generation || len(after.Nodes[0].Health.History) != 0 {
				t.Fatalf("stale check was persisted: snapshot=%+v err=%v", after, err)
			}
		})
	}
}
