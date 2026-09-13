package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/warp"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/security"
)

const awgAPIToken = "awg-test-token-0123456789abcdefghijklmnopqrstuvwxyz"

func awgTestProfile() string {
	k := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	return "[Interface]\nPrivateKey = " + k + "\nAddress = 10.8.0.2/32\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nHeaderProtectionKey = " + k + "\nRandomTrailers = on\n[Peer]\nPublicKey = " + k + "\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
}
func awgAPITest(t *testing.T) (*App, func(string, string, any) *httptest.ResponseRecorder) {
	t.Helper()
	a := autonomyAPIFixture(t)
	a.EngineConfigs = engineconfig.New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
	var err error
	a.Security, err = security.NewGate(awgAPIToken)
	if err != nil {
		t.Fatal(err)
	}
	a.AWGCapabilityProbe = func(context.Context) awgprofile.Capabilities {
		return awgprofile.Capabilities{Backend: "kernel", ToolPath: "/test/awg", ToolVersion: "awg v3.1.20260812", LoadedModuleVersion: "3.1.20260906", ModuleLoaded: true, SupportsAWG31: true}
	}
	send := func(method, path string, body any) *httptest.ResponseRecorder {
		req := autonomyRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer "+awgAPIToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, req)
		return w
	}
	return a, send
}
func TestAWGWorkspaceImportCASAndPrivacy(t *testing.T) {
	a, send := awgAPITest(t)
	w := send("POST", "/api/v1/amneziawg/preview", map[string]any{"content": awgTestProfile()})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var v struct {
		Preview awgprofile.Preview `json:"preview"`
		Base    string             `json:"base_sha256"`
	}
	if json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal("parse")
	}
	if v.Preview.Version != "awg3.1" {
		t.Fatal(v.Preview.Version)
	}
	body := map[string]any{"content": awgTestProfile(), "expected_sha256": v.Preview.SHA256, "base_sha256": v.Base, "confirm": "STAGE_AWG_PROFILE"}
	w = send("POST", "/api/v1/amneziawg/import", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"live_applied":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	staged, err := a.EngineConfigs.ReadExpert("amneziawg", "main")
	if err != nil || !strings.Contains(staged.Content, "HeaderProtectionKey") || staged.Source != "staged" {
		t.Fatal("not staged", err)
	}
	w = send("POST", "/api/v1/amneziawg/import", body)
	if w.Code != 409 {
		t.Fatal("stale import accepted", w.Code)
	}
	w = send("GET", "/api/v1/amneziawg", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "YWFhYWFh") || strings.Contains(w.Body.String(), "private_key") {
		t.Fatal("status secret or failure", w.Code)
	}
	if !a.Store.Get().SafeMode {
		t.Fatal("removed safe mode")
	}
	w = send("POST", "/api/v1/amneziawg/canary", map[string]any{"service_id": "arbitrary-site", "base_sha256": staged.SHA256, "confirm": "PROBE_AWG_PROFILE"})
	if w.Code != 409 {
		t.Fatal("canary in safe mode", w.Code)
	}
}
func TestAWGWorkspaceRejectsMalformedAndUnreviewed(t *testing.T) {
	a, send := awgAPITest(t)
	for _, text := range []string{awgTestProfile() + "\nPostUp = echo secret", strings.Replace(awgTestProfile(), "S4 = 12", "S4 = 0", 1)} {
		if w := send("POST", "/api/v1/amneziawg/preview", map[string]any{"content": text}); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if w := send("POST", "/api/v1/amneziawg/import", map[string]any{"content": awgTestProfile()}); w.Code != 409 {
		t.Fatal(w.Code)
	}
	w := httptest.NewRecorder()
	a.amneziaAPI(w, httptest.NewRequest("GET", "/api/v1/amneziawg", nil))
	if w.Code != 401 {
		t.Fatal("unauthorized", w.Code)
	}
}
func TestAWGUnsupportedCanBeSavedButNeverPretendsReady(t *testing.T) {
	a, send := awgAPITest(t)
	a.AWGCapabilityProbe = func(context.Context) awgprofile.Capabilities { return awgprofile.Capabilities{Backend: "kernel"} }
	w := send("POST", "/api/v1/amneziawg/preview", map[string]any{"content": awgTestProfile()})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "AWG_MODULE_UNSUPPORTED") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOnlyPureHandshakeFailureAuthorizesRefresh(t *testing.T) {
	e := dataplane.WARPHandshakeError{}
	if !strictHandshakeFailure(fmt.Errorf("outer: %w", e)) {
		t.Fatal("typed error rejected")
	}
	for _, e := range []error{errors.New("timeout"), errors.Join(dataplane.WARPHandshakeError{}, errors.New("cleanup failed")), context.Canceled} {
		if strictHandshakeFailure(e) {
			t.Fatal("unsafe class accepted")
		}
	}
}
func TestSafeModeBlocksWarpAccountSideEffects(t *testing.T) {
	a, _ := awgAPITest(t)
	a.Warp = warp.New(t.TempDir(), t.TempDir(), a.EngineConfigs)
	p := a.Warp.Health().Policy
	p.Enabled = true
	p.AcceptTOS = true
	p.AutoGenerateCandidate = true
	p.AllowAccountRefresh = true
	if _, err := a.Warp.UpdateHealthPolicy(p); err != nil {
		t.Fatal(err)
	}
	before := a.Warp.Health()
	d, err := a.processWarpHealth(context.Background(), []warp.HealthEvidence{{ServiceID: "arbitrary-site", Status: "fail", RouteConfirmed: true}})
	if err != nil || d.ShouldGenerate || d.Reason != "safe-mode-blocked-recovery" {
		t.Fatal(err, d.Reason)
	}
	after := a.Warp.Health()
	if before.State.LastChecked != after.State.LastChecked || len(after.State.Attempts) != 0 {
		t.Fatal("Safe Mode wrote recovery state")
	}
}

type awgCanaryAdapter struct{ nodeApplyAdapter }

func (*awgCanaryAdapter) ID() string { return "amneziawg" }

func TestAWGCanaryFencesProfileConfigCatalogRuntimeNetworkAndCancellation(t *testing.T) {
	for _, change := range []string{"none", "profile", "safe-mode", "revision", "catalog", "runtime", "network", "cancel", "after-canary"} {
		t.Run(change, func(t *testing.T) {
			a, _ := awgAPITest(t)
			if err := a.Store.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			view, err := a.EngineConfigs.Stage("amneziawg", "main", awgTestProfile())
			if err != nil {
				t.Fatal(err)
			}
			network, _ := stableNodeProfile(context.Background())
			a.FreshProfile = func(context.Context) (string, error) { return network, nil }
			a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
			adapter := &awgCanaryAdapter{}
			if err := a.Dataplane.Register(adapter); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter.after = func(phase string) error {
				if change == "after-canary" && phase == "canary" {
					network = "wan-abcdef012345"
				}
				if phase != "stage" {
					return nil
				}
				switch change {
				case "profile":
					_, err := a.EngineConfigs.Stage("amneziawg", "main", strings.Replace(awgTestProfile(), "51820", "51821", 1))
					return err
				case "safe-mode":
					return a.Store.SetSafeMode(true)
				case "revision":
					mode := "manual"
					return a.Store.UpdateServiceControl(&mode, nil, a.Store.Get().Revision)
				case "catalog":
					a.Catalog.Services[0].ProbeURL = "https://changed.example/"
				case "runtime":
					a.AWGCapabilityProbe = func(context.Context) awgprofile.Capabilities { return awgprofile.Capabilities{Backend: "kernel"} }
				case "network":
					network = "wan-abcdef012345"
				case "cancel":
					cancel()
				}
				return nil
			}
			request := autonomyRequest("POST", "/api/v1/amneziawg/canary", map[string]any{"service_id": "arbitrary-site", "base_sha256": view.SHA256, "confirm": "PROBE_AWG_PROFILE"}).WithContext(ctx)
			request.Header.Set("Authorization", "Bearer "+awgAPIToken)
			request.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, request)
			if change == "none" {
				if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
					t.Fatal("unchanged isolated proof failed", w.Code, w.Body.String())
				}
			} else if w.Code != 409 || !strings.Contains(w.Body.String(), "AWG_CANARY_CHANGED") {
				t.Fatal("stale isolated proof accepted", change, w.Code, w.Body.String())
			}
			calls := strings.Join(adapter.calls, " ")
			if strings.Contains(calls, "activate") || strings.Contains(calls, "commit") || strings.Contains(calls, "rollback") || change != "none" && change != "after-canary" && strings.Contains(calls, "canary") {
				t.Fatal("stale canary entered later network phase", change, calls)
			}
			entries, err := os.ReadDir(filepath.Join(a.Dataplane.StateRoot, "candidate-probes"))
			if err != nil || len(entries) != 0 {
				t.Fatal("candidate files were not cleaned", err)
			}
		})
	}
}
