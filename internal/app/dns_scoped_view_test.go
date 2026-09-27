package app

import (
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/config"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScopedDNSPanelUsesAppliedDeviceAndDoesNotInventHealth(t *testing.T) {
	a := dnsRuntimeFixture(t)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.41/32"}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://192.168.1.1:8787/api/v1/dns", nil)
	v := a.dnsPanelSnapshot(r).Scoped
	if !v.Available || v.State != "configured" || v.Client != "192.168.1.40" || len(v.Candidates) != 1 || v.Candidates[0].Client != "192.168.1.40" || v.Revision != a.Store.Get().Revision {
		t.Fatalf("wrong observed scope: %+v", v)
	}
	for _, id := range v.Profiles {
		if _, err := a.DNS.ScopedProfileIdentity(id); err != nil {
			t.Fatal("unusable provider exposed", id)
		}
	}
	if out := a.executeServiceRuntime(context.Background(), "stop", a.Store.Get().Revision); out.Code != "" {
		t.Fatal(out)
	}
	v = a.dnsPanelSnapshot(r).Scoped
	if v.State != "stopped" || v.ServiceID != "telegram" || v.ProfileID != "private" || len(v.Candidates) != 0 {
		t.Fatalf("stopped policy hidden or available to apply: %+v", v)
	}
	a.Dataplane = nil
	v = a.dnsPanelSnapshot(r).Scoped
	if v.Available || v.State != "unavailable" || len(v.Candidates) != 0 {
		t.Fatal(v)
	}
}

func TestScopedDNSJobViewContainsScopeButNoReviewAuthority(t *testing.T) {
	_, r := scopedDNSJobFixture(t)
	v := (durableServiceJob{ID: 1, State: "queued", Request: r}).presentation()
	if v.ServiceID != "telegram" || v.DNSApplyAction != "apply" {
		t.Fatal(v)
	}
	data, _ := json.Marshal(v)
	for _, secret := range []string{r.DNSApply.Digest, r.IdempotencyKey, "reviewed_digest", "expected_revision"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("public job leaks authority", secret)
		}
	}
}
