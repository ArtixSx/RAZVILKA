package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func exclusionsHTTPFixture(t *testing.T) (*App, *httptest.Server, map[string]any) {
	t.Helper()
	a, approval := defaultConsentHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	t.Cleanup(server.Close)
	if status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, approval, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal("selected-list source approval", status, string(data))
	}
	return a, server, approval
}

func exclusionPatch(a *App) map[string]any {
	cfg := a.Store.Get()
	r := uint64(0)
	if cfg.NetworkPolicy.Exclusions != nil {
		r = cfg.NetworkPolicy.Exclusions.Revision
	}
	return map[string]any{"expected_revision": cfg.Revision, "expected_policy_revision": cfg.NetworkPolicy.Revision, "expected_exclusion_revision": r}
}

func TestResourceExclusionsActualHTTPAuthCSRFCASAndSeparateIntent(t *testing.T) {
	a, server, _ := exclusionsHTTPFixture(t)
	before := a.Store.Get()
	patch := exclusionPatch(a)
	patch["manual"] = []config.ResourceMatch{{Kind: "service", Value: "video"}, {Kind: "suffix", Value: "example.com"}}
	for _, request := range []struct {
		method, token, origin string
		want                  int
	}{{"GET", componentRecoveryToken, server.URL, 200}, {"POST", "", server.URL, 401}, {"POST", componentRecoveryToken, "https://foreign.example", 403}} {
		if status, _ := componentHTTP(t, server, request.method, resourceExclusionsPath, patch, request.token, request.origin); status != request.want {
			t.Fatal("security", status, request.want)
		}
		if !reflect.DeepEqual(a.Store.Get(), before) {
			t.Fatal("GET/auth/CSRF changed negatives")
		}
	}
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	} else {
		var result struct {
			Revision, PolicyRevision, ExclusionRevision uint64
			LiveApplied                                 bool `json:"live_applied"`
			DesiredMatchesApplied                       bool `json:"desired_matches_applied"`
		}
		if json.Unmarshal(data, &result) != nil || result.LiveApplied || result.DesiredMatchesApplied || result.Revision != before.Revision+1 {
			t.Fatal("intent misreported runtime", string(data))
		}
	}
	after := a.Store.Get()
	if config.CurrentDefaultRouteConsent(after) || after.Revision != before.Revision+1 || after.NetworkPolicy.Revision != before.NetworkPolicy.Revision+1 || after.NetworkPolicy.Exclusions.Revision != 1 || !reflect.DeepEqual(after.AppliedNetworkPolicy, before.AppliedNetworkPolicy) || !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || after.SafeMode != before.SafeMode {
		t.Fatal("edit granted runtime/renewed consent", after)
	}
	if status, _ := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 409 {
		t.Fatal("stale exclusion write", status)
	}
	patch = exclusionPatch(a)
	patch["manual"] = []config.ResourceMatch{}
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 200 || len(a.Store.Get().NetworkPolicy.Exclusions.Manual) != 0 {
		t.Fatal("explicit manual clear", status, string(data))
	}
}

func TestResourceExclusionsHTTPFailedFeedAndNullPatchDoNotClear(t *testing.T) {
	a, server, _ := exclusionsHTTPFixture(t)
	patch := exclusionPatch(a)
	patch["manual"] = []config.ResourceMatch{{Kind: "exact", Value: "manual.example"}}
	feed := &config.AcceptedRussianSnapshot{CatalogID: "reviewed-ru", Revision: 1, Entries: []config.ResourceMatch{{Kind: "service", Value: "bank"}}}
	feed.Digest = config.RussianSnapshotDigest(feed)
	patch["accepted_russian_snapshot"], patch["russian_enabled"] = feed, true
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	}
	before := a.Store.Get()
	for _, kind := range []string{"manual-null", "feed-null", "unknown", "empty-feed", "corrupt-feed", "wrong-policy"} {
		t.Run(kind, func(t *testing.T) {
			patch := exclusionPatch(a)
			patch["manual"] = []config.ResourceMatch{}
			want := 400
			switch kind {
			case "manual-null":
				patch["manual"] = nil
			case "feed-null":
				patch["accepted_russian_snapshot"] = nil
			case "unknown":
				patch["command"] = "clear"
			case "empty-feed":
				f := &config.AcceptedRussianSnapshot{CatalogID: "reviewed-ru", Revision: 2}
				f.Digest = config.RussianSnapshotDigest(f)
				patch["accepted_russian_snapshot"] = f
			case "corrupt-feed":
				f := *feed
				f.Revision = 2
				patch["accepted_russian_snapshot"] = &f
			case "wrong-policy":
				patch["expected_policy_revision"] = uint64(99)
				want = 409
			}
			if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != want {
				t.Fatal(kind, status, string(data))
			}
			if !reflect.DeepEqual(a.Store.Get(), before) {
				t.Fatal("refused source/patch changed negative state")
			}
		})
	}
	patch = exclusionPatch(a)
	patch["russian_enabled"] = false
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	}
	after := a.Store.Get()
	if !reflect.DeepEqual(after.NetworkPolicy.Exclusions.Manual, before.NetworkPolicy.Exclusions.Manual) || !reflect.DeepEqual(after.NetworkPolicy.Exclusions.RussianSnapshot, before.NetworkPolicy.Exclusions.RussianSnapshot) {
		t.Fatal("disable cleared saved exclusions")
	}
}

func TestNetworkPolicyReviewRejectsFullTunnelAndNegativeOverwrite(t *testing.T) {
	a, body := defaultConsentHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	before := a.Store.Get()
	p := body["policy"].(*config.NetworkPolicy)
	p.Traffic = config.TrafficSelection{Mode: "all_except", DefaultRoute: "xray", AllExceptAllowed: true, Unavailable: "retain"}
	if status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status != 400 {
		t.Fatal("legacy full scope accepted", status, string(data))
	}
	if !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("full scope wrote")
	}
	p.Traffic = config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}
	if status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	}
	patch := exclusionPatch(a)
	patch["manual"] = []config.ResourceMatch{{Kind: "service", Value: "video"}}
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	}
	before = a.Store.Get()
	body["expected_revision"] = before.Revision
	body["expected_policy_revision"] = before.NetworkPolicy.Revision
	if status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status != 409 {
		t.Fatal("positive approval overwrote negative", status, string(data))
	}
	if !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("ordinary positive review dropped exclusions")
	}
}

func TestResourceExclusionsFreshInstallReadOnlyAndNoInventedScope(t *testing.T) {
	a, _ := defaultConsentHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	before := a.Store.Get()
	if before.NetworkPolicy != nil {
		t.Fatal("fixture manufactured network scope")
	}
	if status, data := componentHTTP(t, server, "GET", resourceExclusionsPath, nil, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal(status, string(data))
	}
	patch := map[string]any{"expected_revision": before.Revision, "expected_policy_revision": uint64(0), "expected_exclusion_revision": uint64(0), "manual": []config.ResourceMatch{{Kind: "service", Value: "video"}}}
	if status, data := componentHTTP(t, server, "POST", resourceExclusionsPath, patch, componentRecoveryToken, server.URL); status != 503 {
		t.Fatal("missing scope did not explicitly refuse", status, string(data))
	}
	if !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("exclusion save inferred scope/permission")
	}
}
