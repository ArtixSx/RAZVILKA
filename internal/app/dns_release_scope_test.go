package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestDNSReleaseStatusPreservesOrdinaryDNS(t *testing.T) {
	manager, err := dnscontrol.New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{DNS: manager}
	response := httptest.NewRecorder()
	a.dnsDraft(response, httptest.NewRequest(http.MethodPut, "/api/v1/dns/draft", strings.NewReader(`{"profile_id":"ad-block"}`)))
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	before := manager.Snapshot()
	status := httptest.NewRecorder()
	a.dnsStatus(status, httptest.NewRequest(http.MethodGet, "/api/v1/dns", nil))
	var got dnsPanelSnapshot
	if err := json.Unmarshal(status.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if status.Code != http.StatusOK || got.ExperimentalBypass.Available || got.ExperimentalBypass.Code != "EXPERIMENTAL_DNS_BYPASS_DEFERRED" || got.ExperimentalBypass.Reason == "" {
		t.Fatalf("wrong release status: %+v", got.ExperimentalBypass)
	}
	if got.Draft.ProfileID != "ad-block" || got.Applied.ProfileID != "automatic" || len(got.Profiles) == 0 || !reflect.DeepEqual(before, manager.Snapshot()) {
		t.Fatal("release status changed or hid ordinary resolver state")
	}
	// The separately admitted resolver redirect remains available, including
	// its original saved client; synthetic transport availability is unrelated.
	scoped := dnsRuntimeFixture(t)
	v := scoped.dnsPanelSnapshot(httptest.NewRequest(http.MethodGet, "http://192.168.1.1:8787/api/v1/dns", nil))
	if v.ExperimentalBypass.Available || !v.Scoped.Available || v.Scoped.State != "configured" || v.Scoped.Client != "192.168.1.40" {
		t.Fatalf("ordinary scoped DNS lost: %+v", v.Scoped)
	}
}

func TestDNSReleaseScopeKeepsDomainRefusalAndExplicitCIDRs(t *testing.T) {
	for _, route := range []string{"xray", "xray:node", "sing-box", "sing-box:node", "mihomo", "mihomo:node", "wireguard", "wireguard:home", "warp-wg", "amneziawg", "usque"} {
		for _, domain := range []bool{false, true} {
			service := catalog.Service{ID: "scope", CIDRs: []string{"192.0.2.0/24"}}
			if domain {
				service.Domains = []string{"example.com"}
			}
			if routeEligibleForService(service, route) == domain {
				t.Fatalf("AUTO route=%s domain=%v", route, domain)
			}
			input := dataplane.Input{Routes: []dataplane.Route{{ServiceID: service.ID, Resolved: route, Domains: service.Domains, CIDRs: service.CIDRs, Sources: []string{"192.168.1.40/32"}}}}
			plan, err := dataplane.Build(input)
			if err != nil {
				t.Fatal(err)
			}
			blocked := false
			for _, b := range plan.Blockers {
				blocked = blocked || b.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED"
			}
			if blocked != domain || domain && plan.Ready {
				t.Fatalf("route=%s domain=%v blocked=%v ready=%v", route, domain, blocked, plan.Ready)
			}
			if len(plan.Routes) != 1 || plan.Routes[0].Resolved != route || !slices.Equal(plan.Routes[0].Sources, input.Routes[0].Sources) || !slices.Equal(plan.Routes[0].Domains, service.Domains) || !slices.Equal(plan.Routes[0].CIDRs, service.CIDRs) {
				t.Fatal("refusal changed selected route or scope")
			}
		}
	}
	for _, route := range []string{"nfqws2", "direct"} {
		if !routeEligibleForService(catalog.Service{Domains: []string{"example.com"}}, route) {
			t.Fatalf("unrelated hostname/direct path disabled: %s", route)
		}
	}
}
