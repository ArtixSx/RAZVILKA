package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestDefaultConsentColdHTTPAcceptsExplicitEmptyNegativeArrays(t *testing.T) {
	a, body := defaultConsentHTTPFixture(t)
	// Keep the actual browser/native JSON shape. The existing struct fixture
	// otherwise marshals these zero-value Russian arrays as null, hiding the
	// cold first-review bug. This changes only the request used by this test.
	policyJSON := json.RawMessage(`{
		"schema":2,"revision":1,
		"clients":{"mode":"selected_devices","segment_ids":["home"],
			"device_ids":["mac-02-00-00-00-00-01"],"excluded_device_ids":[],
			"excluded_cidrs":[],"new_devices":"base"},
		"traffic":{"mode":"selected_services","all_except_allowed":false,
			"auto_hostlist_allowed":false,"unavailable":"retain"},
		"rules":[],"russian":{"enabled":false,"revision":0,
			"auto_update_allowed":false,"service_ids":[],"broad_tlds":[]}
	}`)
	var requested config.NetworkPolicy
	if err := json.Unmarshal(policyJSON, &requested); err != nil || requested.Russian.ServiceIDs == nil || requested.Russian.BroadTLDs == nil {
		t.Fatal("regression did not preserve the explicit JSON arrays", err)
	}
	body["policy"] = policyJSON
	before := a.Store.Get()
	if before.NetworkPolicy != nil || before.DefaultRouteConsent != nil || a.defaultConsent.owner != nil {
		t.Fatal("regression did not begin with a cold original review")
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, request := range []struct {
		method, token, origin string
		want                  int
	}{{"GET", componentRecoveryToken, server.URL, 200}, {"POST", "", server.URL, 401}, {"POST", componentRecoveryToken, "https://foreign.example", 403}} {
		if status, _ := componentHTTP(t, server, request.method, networkPolicyReviewPath, body, request.token, request.origin); status != request.want {
			t.Fatal("actual auth/CSRF status", status, request.want)
		}
		if !reflect.DeepEqual(a.Store.Get(), before) || a.defaultConsent.owner != nil {
			t.Fatal("read/auth/CSRF created consent or changed the original config")
		}
	}
	status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL)
	if status != 200 {
		t.Fatal("cold original review rejected JSON empty negatives", status, string(data))
	}
	var result struct {
		Approved    bool `json:"approved"`
		LiveApplied bool `json:"live_applied"`
	}
	if err := json.Unmarshal(data, &result); err != nil || !result.Approved || result.LiveApplied {
		t.Fatal("scope approval misreported runtime", err)
	}
	after := a.Store.Get()
	if after.Revision != before.Revision+1 || after.NetworkPolicy.Revision != 1 || !config.CurrentDefaultRouteConsent(after) || after.NetworkPolicy.Russian.ServiceIDs == nil || after.NetworkPolicy.Russian.BroadTLDs == nil || !reflect.DeepEqual(after.DefaultRouteConsent.Grants, body["grants"]) || !reflect.DeepEqual(after.AppliedNetworkPolicy, before.AppliedNetworkPolicy) || !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) {
		t.Fatal("approval changed JSON shape, grants or applied state")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grant := body["grants"].([]config.DefaultRouteGrant)[0]
	review, err := a.ReviewDefaultConsent(ctx, grant.Resolved)
	if err != nil || review.Current(ctx) != nil {
		release()
		t.Fatal("original granted source reader", err)
	}
	release()
	status, data = componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL)
	var stale struct {
		Code string `json:"code"`
	}
	if status != 409 || json.Unmarshal(data, &stale) != nil || stale.Code != "NETWORK_POLICY_REVIEW_CHANGED" || !reflect.DeepEqual(a.Store.Get(), after) {
		t.Fatal("semantic empty comparison waived stale HTTP CAS", status, string(data))
	}
}
