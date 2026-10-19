package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
)

type capabilityRefusalDTO struct {
	OK                   bool   `json:"ok"`
	Code                 string `json:"code"`
	CapabilityRefusal    bool   `json:"capability_refusal"`
	Error                string `json:"error"`
	Resolution           string `json:"resolution"`
	ServiceID            string `json:"service_id"`
	LiveApplied          bool   `json:"live_applied"`
	WorkingRoutesChanged *bool  `json:"working_routes_changed"`
	ReviewRequired       bool   `json:"review_required"`
	Failure              *struct {
		Code, Title, Message, Resolution string
		DraftPreserved                   bool `json:"draft_preserved"`
		Retryable                        bool `json:"retryable"`
	} `json:"failure"`
}

var cyrillicText = regexp.MustCompile(`[А-Яа-яЁё]`)

// Plan and both Apply forms (with and without a reviewed digest) must name
// the same typed, terminal limit and leave the saved draft untouched.
func requireCapabilityRefusal(t *testing.T, a *App, server *httptest.Server, code, serviceID string) capabilityRefusalDTO {
	t.Helper()
	before := a.Store.Get()
	var first capabilityRefusalDTO
	for i, request := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/plan", nil},
		{"POST", "/api/v1/apply", map[string]any{}},
		{"POST", "/api/v1/apply", map[string]any{"expected_revision": before.Revision, "reviewed_digest": strings.Repeat("1", 64)}},
	} {
		status, data := componentHTTP(t, server, request.method, request.path, request.body, componentRecoveryToken, server.URL)
		var got capabilityRefusalDTO
		if status != http.StatusConflict || json.Unmarshal(data, &got) != nil {
			t.Fatalf("%s %s: status=%d body=%s", request.method, request.path, status, data)
		}
		if got.OK || got.Code != code || !got.CapabilityRefusal || got.ServiceID != serviceID || got.LiveApplied || got.WorkingRoutesChanged == nil || *got.WorkingRoutesChanged || got.ReviewRequired {
			t.Fatalf("%s %s: refusal fields %s", request.method, request.path, data)
		}
		if got.Failure == nil || got.Failure.Code != code || got.Failure.Retryable || !got.Failure.DraftPreserved || got.Failure.Message != got.Error || got.Failure.Resolution != got.Resolution {
			t.Fatalf("%s %s: failure advice %s", request.method, request.path, data)
		}
		for _, text := range []string{got.Failure.Title, got.Error, got.Resolution} {
			if !cyrillicText.MatchString(text) || strings.Contains(text, code) || strings.Contains(text, "Safe Mode") {
				t.Fatalf("%s %s: explanation is not a short Russian text: %q", request.method, request.path, text)
			}
		}
		if i == 0 {
			first = got
		} else if got.Error != first.Error || got.Resolution != first.Resolution {
			t.Fatalf("Apply named another limit than the plan: %s", data)
		}
		if !reflect.DeepEqual(a.Store.Get(), before) || a.Operations.Snapshot().Active != 0 {
			t.Fatal("capability refusal mutated Store or retained an operation")
		}
	}
	return first
}

func TestLegacyExecutorRefusalIsTypedConflictNotServerError(t *testing.T) {
	a, _ := defaultConsentHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	patch := exclusionPatch(a)
	patch["manual"] = []config.ResourceMatch{{Kind: "suffix", Value: "example.com"}}
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	}
	got := requireCapabilityRefusal(t, a, server, "NETWORK_POLICY_EXECUTOR_REQUIRED", "")
	if !strings.Contains(got.Error, "Сайты без обхода") || !strings.Contains(got.Resolution, "Очистите") {
		t.Fatalf("inactive-list refusal does not say what to do: %+v", got)
	}
}

func listModeCapabilityFixture(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	a, server, _ := exclusionsHTTPFixture(t)
	if a.Store.Get().NetworkPolicy == nil {
		t.Fatal("fixture has no list policy")
	}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{
		{ID: "video", Name: "Видео", Domains: []string{"video.example"}, ProbeURL: "https://video.example/"},
		{ID: "chat", Name: "Чат", CIDRs: []string{"203.0.113.0/24"}, ProbeURL: "https://chat.example/"},
		{ID: "games", Name: "Игры", CIDRs: []string{"198.51.100.0/24"}, ProbeURL: "https://games.example/"},
	}}
	return a, server
}

func setCapabilityServices(t *testing.T, a *App, routes map[string]string) {
	t.Helper()
	for _, id := range []string{"video", "chat", "games"} {
		route, enabled := routes[id]
		if !enabled {
			route = "direct"
		}
		if err := a.Store.UpdateService(id, config.ServiceState{Enabled: enabled, Route: route}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListModeCapabilityRefusalsAreTypedBeforeAnyLane(t *testing.T) {
	a, server := listModeCapabilityFixture(t)

	setCapabilityServices(t, a, map[string]string{"video": "nfqws2"})
	got := requireCapabilityRefusal(t, a, server, "SERVICE_HAS_DOMAINS", "video")
	if !strings.Contains(got.Error, "«Видео»") || !strings.Contains(got.Error, "CIDR") {
		t.Fatalf("domain refusal does not name the service and the limit: %+v", got)
	}

	setCapabilityServices(t, a, map[string]string{"video": "nfqws2", "chat": "wireguard", "games": "auto"})
	got = requireCapabilityRefusal(t, a, server, "LIST_MODE_SINGLE_SERVICE", "")
	if !strings.Contains(got.Error, "включено 3") || !strings.Contains(got.Resolution, "один сервис") {
		t.Fatalf("single-service refusal does not explain the count: %+v", got)
	}

	// No managed lane covers "auto"; the closed legacy builder answers with
	// the same typed refusal instead of HTTP 500 text.
	setCapabilityServices(t, a, map[string]string{"chat": "auto"})
	got = requireCapabilityRefusal(t, a, server, "NETWORK_POLICY_EXECUTOR_REQUIRED", "")
	if !strings.Contains(got.Resolution, "NFQWS2") {
		t.Fatalf("list-mode refusal names no supported path: %+v", got)
	}
}

// One CIDR-only service with a direct neighbour passes the pre-flight; the
// managed lane still applies its own original-owner refusal.
func TestListModeCapabilityPreflightLeavesLaneRefusalsToLanes(t *testing.T) {
	a, server := listModeCapabilityFixture(t)
	setCapabilityServices(t, a, map[string]string{"chat": "nfqws2", "video": "direct"})
	before := a.Store.Get()
	status, data := componentHTTP(t, server, "GET", "/api/v1/plan", nil, componentRecoveryToken, server.URL)
	if status != http.StatusConflict || strings.Contains(string(data), "capability_refusal") || !strings.Contains(string(data), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
		t.Fatalf("pre-flight replaced the managed lane refusal: %d %s", status, data)
	}
	if !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("lane refusal mutated Store")
	}
}

func TestListModePlatformProfileRefusalUsesStartupStage(t *testing.T) {
	a, server := listModeCapabilityFixture(t)
	setCapabilityServices(t, a, map[string]string{"chat": "nfqws2"})
	a.managedListPolicyMu.Lock()
	a.managedListPolicy = &managedListPolicyOwner{startupFailure: &managedListStartupFailure{stage: "network-identity", cause: errors.New("profile")}}
	a.managedListPolicyMu.Unlock()
	got := requireCapabilityRefusal(t, a, server, "PLATFORM_PROFILE_UNSUPPORTED", "")
	if !strings.Contains(got.Error, "NC-1812") || !strings.Contains(got.Error, "5.01.C.6.0-1") {
		t.Fatalf("platform refusal does not name the supported profile: %+v", got)
	}
	// Another startup stage is not a platform verdict.
	a.managedListPolicyMu.Lock()
	a.managedListPolicy.startupFailure = &managedListStartupFailure{stage: "startup-tools", cause: errors.New("tools")}
	a.managedListPolicyMu.Unlock()
	if status, data := componentHTTP(t, server, "GET", "/api/v1/plan", nil, componentRecoveryToken, server.URL); strings.Contains(string(data), "PLATFORM_PROFILE_UNSUPPORTED") {
		t.Fatalf("non-identity startup failure was reported as an unsupported platform: %d %s", status, data)
	}
}
