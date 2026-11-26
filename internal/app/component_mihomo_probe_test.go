package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestMihomoProbeLineageFallbackRequiresSeparateFreshAdmission(t *testing.T) {
	for _, kind := range []string{"reader5", "reader4", "history5-or-unknown", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []int
			origin, err := chooseMihomoProbeLineage(ctx, func(c context.Context, wanted ...int) error {
				if c != ctx || len(wanted) != 1 {
					t.Fatal("detached admission")
				}
				calls = append(calls, wanted[0])
				if wanted[0] == 5 && kind != "reader5" {
					if kind == "cancel" {
						cancel()
					}
					return errors.New("reader5 refused")
				}
				if wanted[0] == 4 && kind == "history5-or-unknown" {
					return errors.New("reader4 refused retained maximum")
				}
				return nil
			})
			if kind == "reader5" {
				if err != nil || !origin || len(calls) != 1 || calls[0] != 5 {
					t.Fatal(origin, err, calls)
				}
			} else if kind == "reader4" {
				if err != nil || origin || len(calls) != 2 || calls[0] != 5 || calls[1] != 4 {
					t.Fatal(origin, err, calls)
				}
			} else if err == nil || origin || kind == "cancel" && len(calls) != 1 {
				t.Fatal("failed or canceled review became legacy grant", origin, err, calls)
			}
		})
	}
}

func TestMihomoProbeOriginalRequestAdmissionIsExclusiveAndRetainable(t *testing.T) {
	a := &App{}
	var entered atomic.Bool
	server := httptest.NewServer(a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, release, err := a.privateExclusiveOperation(r.Context())
		if err != nil {
			t.Error(err)
			http.Error(w, "admission", 409)
			return
		}
		defer release()
		if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			t.Error(err)
		}
		entered.Store(true)
		w.WriteHeader(204)
	})))
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/api/v1/extension-lab/mihomo", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 || !entered.Load() {
		t.Fatal(response.StatusCode, entered.Load())
	}
}

func TestMihomoProbeEnvironmentClosesCatalogWANConfigAndExclusions(t *testing.T) {
	for _, mutation := range []string{"catalog", "wan", "config", "service-exclusion", "endpoint-exclusion", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			a, _ := awgAPITest(t)
			service := catalog.Service{ID: "video", ProbeURL: "https://example.com/probe", Domains: []string{"example.com"}}
			a.Catalog = catalog.Catalog{Services: []catalog.Service{service}}
			a.FreshProfile = stableNodeProfile
			env, err := newMihomoProbeEnvironment(context.Background(), a, a.Store.Get(), service)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mutation {
			case "catalog":
				a.Catalog.Services[0].Domains[0] = "changed.example"
			case "wan":
				env.fresh = func(context.Context) (string, error) { return "wan-abcdefabcdef", nil }
			case "config":
				if err := a.Store.UpdateService("video", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
					t.Fatal(err)
				}
			case "service-exclusion", "endpoint-exclusion":
				match := config.ResourceMatch{Kind: "service", Value: "video"}
				if mutation == "endpoint-exclusion" {
					match = config.ResourceMatch{Kind: "exact", Value: "edge.example"}
				}
				manual := []config.ResourceMatch{match}
				env.cfg, err = a.Store.UpdateResourceExclusions(ctx, env.cfg, &manual, nil)
				if err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			if err := env.resource(ctx, "edge.example", netip.MustParseAddr("93.184.216.34")); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestMihomoProbeRegistrationBindsOriginalOwners(t *testing.T) {
	a := &App{Components: components.New(), Dataplane: dataplane.New(t.TempDir())}
	provider := netidentity.NewProcProvider()
	if err := a.ConfigureMihomoProbe(provider); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfigureMihomoProbe(provider); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err == nil {
		t.Fatal("replacement provider accepted")
	}
	if !a.mihomoProbeRegistered() {
		t.Fatal("original registration missing")
	}
	if op := a.runtimeLifecycle("mihomo").Operations["isolated_probe"]; op.Registration != "registered" || op.Available != nil {
		t.Fatal("original registration became absent or ready", op)
	}
	// Manager.Register rejects duplicate IDs. Model a defensive exported-slot
	// drift before concurrency; equal IDs/paths cannot replace the actual owner.
	original := a.mihomoProbe.adapter
	a.Dataplane.Adapters["mihomo"] = dataplane.NewMihomoProbeAdapter(a.Components, netidentity.NewProcProvider())
	if a.mihomoProbeRegistered() || a.runtimeLifecycle("mihomo").Operations["isolated_probe"].Registration != "absent" {
		t.Fatal("stale saved registration became current")
	}
	a.Dataplane.Adapters["mihomo"] = original
	a.Components = components.New()
	if a.mihomoProbeRegistered() {
		t.Fatal("replacement component owner accepted")
	}
}

func TestMihomoProbeStatusPublishesSameOriginalLifecycle(t *testing.T) {
	a, send := awgAPITest(t)
	a.Components = components.New()
	a.Dataplane = dataplane.New(t.TempDir())
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	w := send("GET", mihomoProbeRecoveryPath, nil)
	var out struct {
		Lifecycle struct {
			Schema     int `json:"schema"`
			Operations map[string]struct {
				Registration string `json:"registration"`
				Available    *bool  `json:"available"`
			} `json:"operations"`
		} `json:"lifecycle"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	operation := out.Lifecycle.Operations["isolated_probe"]
	if out.Lifecycle.Schema != 1 || operation.Registration != "registered" || operation.Available != nil {
		t.Fatal("status disagrees with original lifecycle", w.Body.String())
	}
	if a.runtimeLifecycle("mihomo").Operations["live_apply"].Registration != "absent" {
		t.Fatal("probe became ordinary route")
	}
}

func TestMihomoProbeHTTPNeverAdoptsSerializedOrUnregisteredSource(t *testing.T) {
	a, _ := awgAPITest(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	send := func(method, path string, body any, origin string) (int, []byte) {
		raw, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var out bytes.Buffer
		out.ReadFrom(response.Body)
		return response.StatusCode, out.Bytes()
	}
	q := ext5Request()
	code, b := send("POST", "/api/v1/extension-lab/mihomo", q, server.URL)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var preview struct {
		Review string `json:"review"`
	}
	json.Unmarshal(b, &preview)
	q["action"], q["confirm"], q["review"] = "probe", "PROBE_MIHOMO_SERVICE", preview.Review
	q["service_id"], q["expected_revision"] = "service", a.Store.Get().Revision
	if code, b = send("POST", "/api/v1/extension-lab/mihomo", q, server.URL); code != 409 || !bytes.Contains(b, []byte("MIHOMO_SERVICE_PROBE_UNCONFIRMED")) {
		t.Fatal(code, string(b))
	}
	if code, _ = send("POST", mihomoProbeRecoveryPath, map[string]string{"confirm": "RETRY_MIHOMO_PROBE_CLEANUP"}, "https://foreign.invalid"); code != 403 {
		t.Fatal("origin bypass", code)
	}
	if code, b = send("GET", mihomoProbeRecoveryPath, nil, server.URL); code != 200 || !bytes.Contains(b, []byte(`"owner_present":false`)) || !bytes.Contains(b, []byte(`"cleanup_confirmed":false`)) {
		t.Fatal(code, string(b))
	}
	if code, b = send("POST", mihomoProbeRecoveryPath, map[string]string{"confirm": "RETRY_MIHOMO_PROBE_CLEANUP", "pid": "123"}, server.URL); code != 400 {
		t.Fatal("serialized adoption", code, string(b))
	}
	q["action"], q["confirm"] = "validate", "VALIDATE_MIHOMO_CONFIG"
	if code, b = send("POST", "/api/v1/extension-lab/mihomo", q, server.URL); code != 409 || !strings.Contains(string(b), "MIHOMO_NATIVE_VALIDATION_UNCONFIRMED") {
		t.Fatal(code, string(b))
	}
}

func TestMihomoProbeColdUnknownStatusNeverAdoptsOrMutates(t *testing.T) {
	a, send := awgAPITest(t)
	root := t.TempDir()
	a.Dataplane = dataplane.New(root)
	path := filepath.Join(root, "latest-execution.json")
	raw := []byte(`{"plan_id":"dp-unknown","state":"resource-failed","resources":[{"kind":"mihomo-probe","phase":"process-unknown"}]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	w := send("GET", mihomoProbeRecoveryPath, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"owner_present":false`) || !strings.Contains(w.Body.String(), `"cleanup_confirmed":false`) || !strings.Contains(w.Body.String(), `"execution_recovery_required":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = send("POST", mihomoProbeRecoveryPath, map[string]string{"confirm": "RETRY_MIHOMO_PROBE_CLEANUP"})
	if w.Code != 409 {
		t.Fatal("cold metadata adopted", w.Code)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("unknown journal changed", err)
	}
}
