package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const xraySelectedQAID = "custom-qa-xray-selected-tcp"
const xraySelectedTelegramDC2 = "149.154.167.51/32"
const xraySelectedMaxResponse = 1 << 20

type xraySelectedNativeInput struct {
	Root, Profile, Catalog, Sources, Scope string
	HTTPS, Client                          netip.Addr
}

// Inputs select files and addresses, never health, receipts, process IDs or
// private runtime authority. The native test validates the existing files too.
func xraySelectedParseInput(getenv func(string) string) (xraySelectedNativeInput, error) {
	var in xraySelectedNativeInput
	for key, target := range map[string]*string{
		"ROOT": &in.Root, "PROFILE": &in.Profile, "CATALOG": &in.Catalog, "SOURCES": &in.Sources, "SCOPE": &in.Scope,
	} {
		*target = getenv("RAZVILKA_NATIVE_XRAY_SELECTED_" + key)
		if !filepath.IsAbs(*target) || filepath.Clean(*target) != *target || strings.TrimSpace(*target) != *target || filepath.Dir(*target) == *target {
			return in, errors.New("explicit canonical QA input required")
		}
	}
	var err error
	in.HTTPS, err = netip.ParseAddr(getenv("RAZVILKA_NATIVE_XRAY_SELECTED_HTTPS_IPV4"))
	if err != nil || !in.HTTPS.Is4() || !publicfetch.PublicAddress(in.HTTPS) {
		return in, errors.New("public HTTPS IPv4 required")
	}
	in.Client, err = netip.ParseAddr(getenv("RAZVILKA_NATIVE_XRAY_SELECTED_CLIENT_IPV4"))
	if err != nil || !in.Client.Is4() || !in.Client.IsGlobalUnicast() || in.Client.IsLoopback() {
		return in, errors.New("selected LAN client IPv4 required")
	}
	return in, nil
}

func xraySelectedQAService(pin netip.Addr) catalog.Service {
	cidrs := []string{pin.String() + "/32", xraySelectedTelegramDC2}
	slices.Sort(cidrs)
	return catalog.Service{ID: xraySelectedQAID, Name: "QA Xray selected TCP", Category: "QA", Icon: "+",
		Description: "Separate IPv4 TCP QA definition; not the built-in Telegram service or authenticated Telegram acceptance",
		Domains:     []string{}, CIDRs: slices.Compact(cidrs), Strategy: []string{"xray"}, ProbeURL: "https://telegram.org/",
		Probes: []catalog.Probe{{ID: "qa-https", Label: "Public Telegram HTTPS only", URL: "https://telegram.org/", Required: true,
			Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "none"}}}}
}

// This is intent read from Root's chosen file, not a READY/scope observation.
// Preserve selected device/segment IDs; prohibit broad or unrelated rules.
func xraySelectedScope(data []byte) (*config.NetworkPolicy, error) {
	var p config.NetworkPolicy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(&struct{}{}) != io.EOF || p.Schema != 2 ||
		p.Clients.Mode != "selected_devices" || len(p.Clients.DeviceIDs) != 1 || len(p.Clients.SegmentIDs) != 1 ||
		p.Traffic.Mode != "selected_services" || len(p.Rules) != 0 || p.Exclusions != nil || p.Russian.Enabled {
		return nil, errors.New("one selected device list-only scope intent required")
	}
	p.Revision = 1
	p.Rules = []config.NetworkRule{{ID: "qa-selected-tcp", Revision: 1, Kind: "service", Value: xraySelectedQAID, Action: "bypass"}}
	if config.ValidateListNetworkPolicy(&p) != nil {
		return nil, errors.New("invalid scope intent")
	}
	return &p, nil
}

// Never print a response body/raw error: private import/parser errors can carry
// profile material. Only known fixed production refusal codes may be reported.
func xraySelectedRefusal(data []byte) string {
	for _, code := range []string{
		"NODE_HISTORY_ADMISSION_REQUIRED", "NODE_RESOURCE_REFUSED", "NODE_CLEANUP_REQUIRED", "NODE_CHECK_DEADLINE", "NODE_CHECK_CANCELED",
		"NETWORK_POLICY_EXECUTOR_REQUIRED", "NETWORK_POLICY_CONSENT_UNAVAILABLE", "NETWORK_POLICY_PROFILE_OWNER_REQUIRED", "NETWORK_POLICY_SOURCE_UNKNOWN",
		"NETWORK_POLICY_LIST_REQUIRED", "APPLY_REVIEW_CHANGED", "ROUTE_UNAVAILABLE", "SERVICE_RUNTIME_CHANGED", "SERVICE_RUNTIME_CHECK_REQUIRED",
		"SERVICE_RUNTIME_SAFE_MODE", "SERVICE_RUNTIME_UNAVAILABLE", "SERVICE_RUNTIME_UNCONFIGURED", "SERVICE_CONTROL_CHANGED",
		"node-service-ip-path-failed", "node-service-ip-unavailable", "node-service-probe-failed", "node-cleanup-failed", "node-check-deadline",
	} {
		if bytes.Contains(data, []byte(code)) {
			return code
		}
	}
	return "production_refused"
}

func xraySelectedCall(ctx context.Context, client *http.Client, base, token, method, route string, value any) (int, []byte, error) {
	var payload []byte
	var err error
	if value != nil {
		payload, err = json.Marshal(value)
		if err != nil {
			return 0, nil, errors.New("request unavailable")
		}
	}
	defer clear(payload)
	request, err := http.NewRequestWithContext(ctx, method, base+route, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, errors.New("request unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Origin", base)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, errors.New("HTTP operation incomplete")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, xraySelectedMaxResponse+1))
	if err != nil || len(data) > xraySelectedMaxResponse {
		clear(data)
		return response.StatusCode, nil, errors.New("response incomplete or over limit")
	}
	return response.StatusCode, data, nil
}

func TestXraySelectedNativeInputAndScopeRejectWidening(t *testing.T) {
	root := filepath.Join(t.TempDir(), "qa")
	values := map[string]string{"ROOT": root, "PROFILE": filepath.Join(root, "selected-profile"), "CATALOG": filepath.Join(root, "catalog.json"),
		"SOURCES": filepath.Join(root, "sources.json"), "SCOPE": filepath.Join(root, "scope.json"), "HTTPS_IPV4": "149.154.167.99", "CLIENT_IPV4": "192.168.1.100"}
	get := func(key string) string { return values[strings.TrimPrefix(key, "RAZVILKA_NATIVE_XRAY_SELECTED_")] }
	if _, err := xraySelectedParseInput(get); err != nil {
		t.Fatal("valid path/address contract rejected")
	}
	for _, key := range []string{"PROFILE", "HTTPS_IPV4", "CLIENT_IPV4"} {
		old := values[key]
		values[key] = "vless://UUID:PRIVATE-KEY@private.invalid/"
		if _, err := xraySelectedParseInput(get); err == nil {
			t.Fatal("invalid path/address accepted")
		}
		values[key] = old
	}
	p := config.NetworkPolicy{Schema: 2, Clients: config.ClientScope{Mode: "selected_devices", SegmentIDs: []string{"actual-segment-id"}, DeviceIDs: []string{"actual-device-id"}, NewDevices: "base"},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	data, _ := json.Marshal(p)
	approved, err := xraySelectedScope(data)
	if err != nil || len(approved.Rules) != 1 || approved.Rules[0].Value != xraySelectedQAID {
		t.Fatal("one-device intent did not retain its exact QA rule")
	}
	for _, cut := range []string{"all-except", "multiple-devices", "unrelated-rule", "ready-dto"} {
		changed := config.CloneNetworkPolicy(&p)
		switch cut {
		case "all-except":
			changed.Traffic.Mode = "all_except"
		case "multiple-devices":
			changed.Clients.DeviceIDs = append(changed.Clients.DeviceIDs, "second-device")
		case "unrelated-rule":
			changed.Rules = []config.NetworkRule{{Kind: "cidr", Value: "0.0.0.0/0"}}
		}
		data, _ := json.Marshal(changed)
		if cut == "ready-dto" {
			data = append(data[:len(data)-1], []byte(`,"ready":true}`)...)
		}
		if _, err := xraySelectedScope(data); err == nil {
			t.Fatal("scope widening or runtime DTO accepted", cut)
		}
	}
	service := xraySelectedQAService(netip.MustParseAddr(values["HTTPS_IPV4"]))
	if len(service.Domains) != 0 || len(service.CIDRs) != 2 || service.ID == "telegram" || service.ProbeURL != "https://telegram.org/" || catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}) != nil {
		t.Fatal("QA definition replaced built-in domains or widened its destinations")
	}
}

func TestXraySelectedNativeHTTPBoundsAndRefusalPrivacy(t *testing.T) {
	const secret = "vless://UUID:PRIVATE-KEY@private.invalid/"
	for _, body := range []string{secret, `{"error":"` + secret + `","code":"PRIVATE-KEY"}`, `{"code":"NODE_HISTORY_ADMISSION_REQUIRED","error":"` + secret + `"}`} {
		code := xraySelectedRefusal([]byte(body))
		if strings.Contains(code, "PRIVATE") || strings.Contains(code, "UUID") || strings.Contains(code, "://") {
			t.Fatal("refusal output exposed raw material")
		}
	}
	if xraySelectedRefusal([]byte("NETWORK_POLICY_EXECUTOR_REQUIRED: existing route unchanged")) != "NETWORK_POLICY_EXECUTOR_REQUIRED" {
		t.Fatal("current production blocker was hidden")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-test-token" || r.Header.Get("Origin") == "" {
			t.Error("authenticated request contract lost")
		}
		_, _ = io.WriteString(w, strings.Repeat("x", xraySelectedMaxResponse+1))
	}))
	defer server.Close()
	status, data, err := xraySelectedCall(context.Background(), server.Client(), server.URL, "owned-test-token", "POST", "/fixture", map[string]string{"profile": secret})
	if status != 200 || data != nil || err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unbounded response or raw request data escaped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := xraySelectedCall(ctx, server.Client(), server.URL, "owned-test-token", "GET", "/fixture", nil); err == nil {
		t.Fatal("canceled HTTP request completed")
	}
}
