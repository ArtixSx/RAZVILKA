package app

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func openMihomoStoredProbeTestStore(t *testing.T) *nodestore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestMihomoStoredProbeBindsExactLibrarySourceAndRefusesRawOverride(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store := openMihomoStoredProbeTestStore(t)
	view, err := store.ImportPersonal(ctx, "vless://123e4567-e89b-12d3-a456-426614174001@stored-mihomo.example:443?security=tls", time.Now(), time.Hour, false, false)
	if err != nil || len(view.Nodes) != 1 {
		t.Fatal("import original candidate", err)
	}
	app := &App{Nodes: store}
	id := view.Nodes[0].ID
	source, err := app.reviewMihomoStoredProbe(ctx, id)
	if err != nil || source.node.Reference().NodeID != id || source.node.Reference().NodeGeneration != view.Generation {
		t.Fatal("stored candidate did not bind original library", err)
	}
	raw, err := source.profile(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	profile, err := backendprofile.Mihomo(string(raw), backendprofile.MihomoOptions{SOCKSPort: mihomoStoredProbePort})
	if err != nil || len(profile.Source.Nodes) != 1 || profile.Source.Nodes[0].Server != "stored-mihomo.example" {
		t.Fatal("stored input lost the real reviewed endpoint", err)
	}
	for _, p := range []mihomoProbeInput{{stored: source, raw: "replacement"}, {stored: source, review: "replacement"}, {stored: source, options: backendprofile.MihomoOptions{SOCKSPort: 18085}}} {
		if !errors.Is(p.current(ctx, app), dataplane.ErrNodeDefaultSource) {
			t.Fatal("raw input overrode the original catalog candidate")
		}
	}
	copySource := *source
	if !errors.Is(copySource.current(ctx, app), dataplane.ErrNodeDefaultSource) || !errors.Is(source.current(ctx, &App{Nodes: store}), dataplane.ErrNodeDefaultSource) {
		t.Fatal("copied or foreign App adopted the source")
	}
	if _, err := store.SetDisabled(ctx, id, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if raw, err := source.profile(ctx, app); len(raw) != 0 || !errors.Is(err, dataplane.ErrNodeDefaultSource) {
		t.Fatal("revoked candidate retained material", err)
	}
}

func TestMihomoStoredProbeRefusesPublicOnlyOrExpiredPersonalOrigin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store := openMihomoStoredProbeTestStore(t)
	app := &App{Nodes: store}
	now := time.Now()
	raw := "vless://123e4567-e89b-12d3-a456-426614174001@stored-mihomo.example:443?security=tls"
	view, err := store.Import(ctx, nodestore.Source{ID: "public", Kind: "community"}, raw, now.Add(-2*time.Hour), 3*time.Hour, false)
	if err != nil || len(view.Nodes) != 1 {
		t.Fatal("import public candidate", err)
	}
	id := view.Nodes[0].ID
	if source, err := app.reviewMihomoStoredProbe(ctx, id); source != nil || !errors.Is(err, dataplane.ErrNodeDefaultSource) {
		t.Fatal("stored check admitted public-only profile", err)
	}
	if _, err := store.ImportPersonal(ctx, raw, now.Add(-2*time.Hour), time.Hour, false, false); err != nil {
		t.Fatal(err)
	}
	if source, err := app.reviewMihomoStoredProbe(ctx, id); source != nil || !errors.Is(err, dataplane.ErrNodeDefaultSource) {
		t.Fatal("fresh public origin replaced an expired personal origin", err)
	}
	if _, err := store.ImportPersonal(ctx, raw, now, time.Hour, false, false); err != nil {
		t.Fatal(err)
	}
	if source, err := app.reviewMihomoStoredProbe(ctx, id); source == nil || err != nil || !source.expires.Equal(now.Add(time.Hour)) {
		t.Fatal("current personal origin did not bind this exact candidate", err)
	}
}

func TestExtensionMihomoStoredProbeRequiresExactAuthenticatedRequest(t *testing.T) {
	a, send := awgAPITest(t)
	a.Nodes = openMihomoStoredProbeTestStore(t)
	a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "test-site", Name: "Test", ProbeURL: "https://example.org/"}}}
	ctx := context.Background()
	view, err := a.Nodes.ImportPersonal(ctx, ext5Request()["content"].(string), time.Now(), time.Hour, false, false)
	if err != nil || len(view.Nodes) != 1 {
		t.Fatal("import test profile", err)
	}
	before := a.Store.Get()
	const path = "/api/v1/extension-lab/mihomo"
	request := map[string]any{
		"action": "probe-stored", "confirm": "PROBE_MIHOMO_SERVICE", "node_id": view.Nodes[0].ID,
		"expected_node_generation": view.Generation, "service_id": "test-site", "expected_revision": before.Revision,
	}
	for _, test := range []struct {
		auth   bool
		origin string
		status int
	}{
		{false, "", http.StatusUnauthorized},
		{true, "https://foreign.invalid", http.StatusForbidden},
	} {
		r := autonomyRequest(http.MethodPost, path, request)
		r.Header.Set("Content-Type", "application/json")
		if test.auth {
			r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		}
		if test.origin != "" {
			r.Header.Set("Origin", test.origin)
		}
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatal("stored check escaped existing authentication/origin gate", w.Code, test.status)
		}
	}
	for key, value := range map[string]any{"content": "", "options": nil, "review": nil, "expected_node_generation": 0, "expected_revision": nil, "confirm": "BUILD_MIHOMO_CONFIG", "endpoint": "1.1.1.1"} {
		candidate := maps.Clone(request)
		candidate[key] = value
		if w := send(http.MethodPost, path, candidate); w.Code != http.StatusBadRequest {
			t.Fatal("mixed or unconfirmed stored input accepted", key, w.Code)
		}
	}
	for _, field := range []string{"node_id", "expected_node_generation"} {
		oldClient := ext5Request()
		oldClient[field] = nil
		if w := send(http.MethodPost, path, oldClient); w.Code != http.StatusBadRequest {
			t.Fatal("raw action accepted typed profile fields", field, w.Code)
		}
	}
	staleConfig := maps.Clone(request)
	staleConfig["expected_revision"] = before.Revision + 1
	_, closeGate, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	busy := send(http.MethodPost, path, staleConfig)
	closeGate()
	if busy.Code != http.StatusConflict || !strings.Contains(busy.Body.String(), "RESTORE_OPERATION_BUSY") || strings.Contains(busy.Body.String(), "MIHOMO_REVIEW_CHANGED") {
		t.Fatal("stored request reached Store review while another owner held the gate", busy.Code)
	}
	if w := send(http.MethodPost, path, staleConfig); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "MIHOMO_REVIEW_CHANGED") {
		t.Fatal("stale settings passed original admission", w.Code)
	}
	if _, err := a.Nodes.SetAlias(ctx, view.Nodes[0].ID, "later generation", time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := send(http.MethodPost, path, request); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "MIHOMO_STORED_PROFILE_UNAVAILABLE") {
		t.Fatal("stale stored generation passed original admission", w.Code)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || a.mihomoProbe.held != nil {
		t.Fatal("refused stored request changed settings or acquired probe resources")
	}
}
