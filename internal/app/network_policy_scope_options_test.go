package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func scopeOptionsFileImages(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(d.Name(), ".lock") {
			// Original private owners intentionally hold Windows file locks.
			info, err := d.Info()
			if err != nil {
				return err
			}
			out[path] = sha256.Sum256([]byte(info.ModTime().String()))
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNetworkPolicyScopeOptionsActualHTTPAuthMethodAndNoDiscoveryWrites(t *testing.T) {
	a, _ := defaultConsentHTTPFixture(t)
	root := filepath.Dir(a.defaultConsent.configPath)
	var err error
	a.Devices, err = devices.Load(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	before, files := a.Store.Get(), scopeOptionsFileImages(t, root)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, request := range []struct {
		method, token, path string
		status              int
	}{{"GET", "", networkPolicyScopeOptionsPath, 401}, {"POST", componentRecoveryToken, networkPolicyScopeOptionsPath, 405}, {"GET", componentRecoveryToken, networkPolicyScopeOptionsPath + "?segment=guessed", 400}, {"GET", componentRecoveryToken, networkPolicyScopeOptionsPath, 200}} {
		req, err := http.NewRequest(request.method, server.URL+request.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		if request.token != "" {
			req.Header.Set("Authorization", "Bearer "+request.token)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("scope response read/cache policy", err)
		}
		status := res.StatusCode
		if status != request.status {
			t.Fatal("unexpected HTTP result", request.method, status, request.status)
		}
		if status == 200 {
			var response networkPolicyScopeOptionsResponse
			if json.Unmarshal(data, &response) != nil || response.Schema != 1 || !response.OK || response.PolicyRevision != 0 || response.Revision != before.Revision || response.EffectAuthorized || response.LiveApplied || response.Segments == nil || response.Devices == nil || response.RetainedDeviceIDs == nil || response.RetainedSegmentIDs == nil {
				t.Fatal("first-setup observation granted effects or omitted arrays")
			}
		}
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(files, scopeOptionsFileImages(t, root)) {
		t.Fatal("scope GET changed config, discovery disk or private owners")
	}
	if a.Dataplane != nil || a.managedListPolicy != nil {
		t.Fatal("read created runtime authority")
	}
}

func scopeOptionsObservedModel() physicalscope.ScopeOptionsObservation {
	now := time.Now().UTC()
	until := now.Add(physicalscope.ScopeOptionsFreshness)
	name, iface, segment := "Home", "br0", "Bridge0"
	return physicalscope.ScopeOptionsObservation{State: "available", Code: "OBSERVED", ObservedAt: &now, FreshUntil: &until,
		Segments: []physicalscope.ScopeSegmentOption{{ID: segment, Label: name, NativeName: &name, Interface: &iface, State: "observed", Code: "OBSERVED_HOME", SelectionCandidate: true}},
		Devices:  []physicalscope.ScopeDeviceOption{{ID: "mac-02-00-00-00-00-40", Label: "mac-02-00-00-00-00-40", SegmentID: &segment, State: "observed", Code: "OBSERVED_DEVICE", SelectionCandidate: true}}}
}

func TestNetworkPolicyScopeOptionsRetainsAliasesOfflineAndAppliedRefsOnBounds(t *testing.T) {
	cfg := config.Default()
	cfg.Revision = 8
	cfg.NetworkPolicy = &config.NetworkPolicy{Revision: 3, Clients: config.ClientScope{SegmentIDs: []string{"Home", "missing-home"}, ExcludedDeviceIDs: []string{"offline-device", "unknown-device"}}}
	cfg.AppliedNetworkPolicy = &config.NetworkPolicy{Clients: config.ClientScope{SegmentIDs: []string{"old-home"}, DeviceIDs: []string{"old-device"}}}
	before := config.CloneNetworkPolicy(cfg.NetworkPolicy)
	for _, kind := range []string{"observed", "partial", "unavailable", "device-bound", "segment-bound"} {
		t.Run(kind, func(t *testing.T) {
			model := scopeOptionsObservedModel()
			switch kind {
			case "partial":
				model.State = "partial"
			case "unavailable":
				model = scopeOptionsUnavailable("SOURCE_UNAVAILABLE")
			case "device-bound":
				model.Devices = make([]physicalscope.ScopeDeviceOption, 513)
			case "segment-bound":
				model.Segments = make([]physicalscope.ScopeSegmentOption, 17)
			}
			r := networkPolicyScopeOptionsView(cfg, model)
			if !slices.Equal(r.RetainedSegmentIDs, []string{"Home", "missing-home", "old-home"}) || !slices.Equal(r.RetainedDeviceIDs, []string{"offline-device", "old-device", "unknown-device"}) || !reflect.DeepEqual(before, cfg.NetworkPolicy) || r.EffectAuthorized || r.LiveApplied {
				t.Fatal("saved refs normalized, intersected discovery or granted effects")
			}
			for _, id := range r.RetainedDeviceIDs {
				i := slices.IndexFunc(r.Devices, func(d physicalscope.ScopeDeviceOption) bool { return d.ID == id })
				if i < 0 || r.Devices[i].SegmentID != nil || r.Devices[i].SelectionCandidate {
					t.Fatal("offline/unknown ref dropped or got cached association")
				}
			}
			if kind == "observed" && slices.ContainsFunc(r.Segments, func(s physicalscope.ScopeSegmentOption) bool { return s.ID == "Home" }) {
				t.Fatal("unique raw alias became a fabricated canonical option")
			}
			if (kind == "device-bound" || kind == "segment-bound") && (r.State != "unavailable" || r.Code != "BOUNDS_EXCEEDED") {
				t.Fatal("observation bound failure concealed")
			}
		})
	}
}

func TestNetworkPolicyScopeOptionsFreshFirstSetupCancellationAndRevisionDrift(t *testing.T) {
	a, _ := defaultConsentHTTPFixture(t)
	read := func(t *testing.T, ctx context.Context, source func(context.Context) physicalscope.ScopeOptionsObservation) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest("GET", networkPolicyScopeOptionsPath, nil).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+componentRecoveryToken)
		w := httptest.NewRecorder()
		a.networkPolicyScopeOptionsRead(w, request, source)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("observation can be cached")
		}
		return w
	}
	w := read(t, context.Background(), func(ctx context.Context) physicalscope.ScopeOptionsObservation {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > physicalscope.ScopeOptionsTimeout {
			t.Fatal("source budget not bounded")
		}
		return scopeOptionsObservedModel()
	})
	var response networkPolicyScopeOptionsResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.PolicyRevision != 0 || response.State != "available" || len(response.Segments) != 1 || a.Store.Get().NetworkPolicy != nil {
		t.Fatal("fresh first setup depended on an approved policy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	joined := false
	w = read(t, ctx, func(ctx context.Context) physicalscope.ScopeOptionsObservation {
		<-ctx.Done()
		joined = true
		return scopeOptionsObservedModel() // Even a late positive cannot escape cancellation.
	})
	if !joined || w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.State != "unavailable" || response.Code != "SOURCE_TIMEOUT" || len(response.Segments) != 0 {
		t.Fatal("canceled read published positive candidates")
	}
	w = read(t, context.Background(), func(context.Context) physicalscope.ScopeOptionsObservation {
		if err := a.Store.UpdateService("changed", config.ServiceState{Enabled: false, Route: "direct"}); err != nil {
			t.Fatal(err)
		}
		return scopeOptionsObservedModel()
	})
	if w.Code != 409 {
		t.Fatal("mixed revisions returned choices", w.Code)
	}
}

func TestNetworkPolicyScopeOptionsAllSavedRefsAndResponseBound(t *testing.T) {
	cfg := config.Default()
	cfg.NetworkPolicy, cfg.AppliedNetworkPolicy = &config.NetworkPolicy{}, &config.NetworkPolicy{}
	for side, p := range []*config.NetworkPolicy{cfg.NetworkPolicy, cfg.AppliedNetworkPolicy} {
		for i := 0; i < 16; i++ {
			p.Clients.SegmentIDs = append(p.Clients.SegmentIDs, fmt.Sprintf("saved-segment-%d-%d", side, i))
		}
		for i := 0; i < 128; i++ {
			p.Clients.DeviceIDs = append(p.Clients.DeviceIDs, fmt.Sprintf("saved-selected-%d-%d", side, i))
			p.Clients.ExcludedDeviceIDs = append(p.Clients.ExcludedDeviceIDs, fmt.Sprintf("saved-excluded-%d-%d", side, i))
		}
	}
	r := networkPolicyScopeOptionsView(cfg, scopeOptionsUnavailable("BOUNDS_EXCEEDED"))
	if len(r.RetainedSegmentIDs) != 32 || len(r.RetainedDeviceIDs) != 512 || len(r.Segments) != 32 || len(r.Devices) != 512 {
		t.Fatal("maximum bounded saved refs were silently dropped")
	}
	a, approval := defaultConsentHTTPFixture(t)
	approval["policy"].(*config.NetworkPolicy).Clients.ExcludedDeviceIDs = []string{"saved-offline"}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	if status, _ := componentHTTP(t, server, "POST", networkPolicyReviewPath, approval, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal("original explicit policy approval failed", status)
	}
	before := a.Store.Get()
	request := httptest.NewRequest("GET", networkPolicyScopeOptionsPath, nil)
	request.Header.Set("Authorization", "Bearer "+componentRecoveryToken)
	w := httptest.NewRecorder()
	a.networkPolicyScopeOptionsRead(w, request, func(context.Context) physicalscope.ScopeOptionsObservation {
		model := scopeOptionsObservedModel()
		model.Devices[0].Label = strings.Repeat("x", 1<<20)
		return model
	})
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &r) != nil || r.Code != "BOUNDS_EXCEEDED" || !slices.Equal(r.RetainedDeviceIDs, []string{"saved-offline"}) || len(r.Devices) != 1 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("response bound erased refs or wrote policy", w.Code)
	}
}
