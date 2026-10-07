package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
)

func defaultConsentHTTPFixture(t *testing.T) (*App, map[string]any) {
	t.Helper()
	base := t.TempDir()
	cfgPath := filepath.Join(base, "config.json")
	nodeRoot := filepath.Join(base, "nodes")
	if err := os.Mkdir(nodeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	snapshot, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@owned-fixture.example:443?security=tls&sni=owned-fixture.example", time.Now().UTC(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Nodes: nodes, Security: sec, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: control}}
	if err := a.ConfigureDefaultConsent(cfgPath, nodeRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseDefaultConsent() })
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "all_except", DefaultRoute: "xray", AllExceptAllowed: true, Unavailable: "retain"}}
	g := config.DefaultRouteGrant{Resolved: "xray:" + snapshot.Nodes[0].ID, ProviderClass: "node", ProviderID: snapshot.Nodes[0].ID, SourceIDs: []string{"manual"}, SourceKinds: []string{"manual"}, Protocols: []string{"vless"}}
	return a, map[string]any{"expected_revision": store.Get().Revision, "expected_policy_revision": uint64(0), "policy": policy, "grants": []config.DefaultRouteGrant{g}, "confirm": "APPROVE_NETWORK_POLICY"}
}

func TestDefaultConsentActualHTTPAuthCSRFCASAndConcreteReader(t *testing.T) {
	a, body := defaultConsentHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	before := a.Store.Get()
	for _, request := range []struct {
		method, token, origin string
		want                  int
	}{{"GET", componentRecoveryToken, server.URL, 200}, {"POST", "", server.URL, 401}, {"POST", componentRecoveryToken, "https://foreign.example", 403}} {
		if status, _ := componentHTTP(t, server, request.method, networkPolicyReviewPath, body, request.token, request.origin); status != request.want {
			t.Fatal("security status", status, request.want)
		}
		if !reflect.DeepEqual(a.Store.Get(), before) {
			t.Fatal("read/auth/CSRF issued approval")
		}
	}
	if status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal("real review CAS", status, string(data))
	} else {
		var result struct {
			Approved    bool `json:"approved"`
			LiveApplied bool `json:"live_applied"`
		}
		if json.Unmarshal(data, &result) != nil || !result.Approved || result.LiveApplied {
			t.Fatal("approval misreported runtime")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grant := body["grants"].([]config.DefaultRouteGrant)[0]
	review, err := a.ReviewDefaultConsent(ctx, grant.Resolved)
	if err != nil {
		release()
		t.Fatal("production reader", err)
	}
	if err := review.Current(ctx); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if status, _ := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status != 409 {
		t.Fatal("stale explicit approval accepted", status)
	}
}

func TestDefaultConsentHTTPRequiresConfirmKnownSourceAndExistingControl(t *testing.T) {
	for _, kind := range []string{"confirm", "source", "control"} {
		t.Run(kind, func(t *testing.T) {
			a, body := defaultConsentHTTPFixture(t)
			before := a.Store.Get()
			switch kind {
			case "confirm":
				body["confirm"] = ""
			case "source":
				g := body["grants"].([]config.DefaultRouteGrant)
				g[0].SourceIDs = []string{"unknown"}
			case "control":
				a.SelfUpdateFiles.ControlRoot = filepath.Join(t.TempDir(), "missing")
			}
			server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer server.Close()
			if status, _ := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status == 200 {
				t.Fatal("unconfirmed/unknown/unbound approval accepted")
			}
			if !reflect.DeepEqual(a.Store.Get(), before) {
				t.Fatal("refused review changed config")
			}
		})
	}
}
