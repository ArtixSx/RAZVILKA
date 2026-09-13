package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// All request cases below terminate before external DNS. The DNS manager's
// exchange injection tests cover actual query calls in its own package.
func TestDNSServiceComparisonHTTPGuards(t *testing.T) {
	a, send := awgAPITest(t)
	var err error
	a.DNS, err = dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	rev := a.Store.Get().Revision
	body := func() map[string]any {
		return map[string]any{"service_id": "arbitrary-site", "profile_ids": []string{"private"}, "config_revision": rev, "confirm": "COMPARE_SERVICE_DNS"}
	}
	before := a.Store.Get()
	for _, c := range []struct {
		name, method string
		want         int
		mutate       func(map[string]any)
	}{
		{"wrong-method", "GET", 405, func(map[string]any) {}},
		{"consent", "POST", 400, func(q map[string]any) { delete(q, "confirm") }},
		{"unknown-field", "POST", 400, func(q map[string]any) { q["url"] = "https://private.example" }},
		{"stale-revision", "POST", 409, func(q map[string]any) { q["config_revision"] = rev + 1 }},
		{"missing-service", "POST", 404, func(q map[string]any) { q["service_id"] = "does-not-exist" }},
		{"invalid-profile", "POST", 400, func(q map[string]any) { q["profile_ids"] = []string{"does-not-exist"} }},
		{"unconfigured-profile", "POST", 400, func(q map[string]any) { q["profile_ids"] = []string{"geohide"} }},
		{"empty-profiles", "POST", 400, func(q map[string]any) { q["profile_ids"] = []string{} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := body()
			c.mutate(q)
			w := send(c.method, "/api/v1/dns/service-compare", q)
			if w.Code != c.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("read-only comparison changed config")
	}
	raw, _ := json.Marshal(body())
	r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/service-compare", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	a.dnsServiceCompare(w, r)
	if w.Code != 401 {
		t.Fatal("unauthenticated", w.Code)
	}
}
