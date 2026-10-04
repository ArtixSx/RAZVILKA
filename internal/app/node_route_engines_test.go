package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/security"
)

// All adapter effects are modeled. This verifies app transaction bindings,
// not native Xray/TUN or selected/control LAN acceptance.
type xrayApplyFixtureAdapter struct{ *nodeApplyAdapter }

func (*xrayApplyFixtureAdapter) ID() string { return "xray" }

func xrayRouteFixture(t *testing.T, proof bool) (*App, string, *nodeApplyAdapter, *nodeApplyAdapter) {
	t.Helper()
	a, id, sing := nodeApplyFixture(t)
	if proof {
		at := time.Now()
		_, err := a.Nodes.RecordCheck(context.Background(), id, nodestore.CheckRecord{ProbeID: "xray-app-route-proof", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "xray:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: at, ExpiresAt: at.Add(time.Hour)}, at)
		if err != nil {
			t.Fatal(err)
		}
	}
	xray := &nodeApplyAdapter{}
	if err := a.Dataplane.Register(&xrayApplyFixtureAdapter{xray}); err != nil {
		t.Fatal(err)
	}
	oldOptions := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(oldOptions(), routecatalog.Option{ID: "xray", Installed: true, Configured: true, Selectable: true},
			routecatalog.Option{ID: "xray:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"telegram"}})
	}
	a.NodeHistoryWriteGuard = func(ctx context.Context, required int) error {
		if required != 2 {
			return errors.New("wrong history capability")
		}
		return ctx.Err()
	}
	a.Security, _ = security.NewGate(componentRecoveryToken)
	return a, id, sing, xray
}

func previewXrayHTTP(t *testing.T, s *httptest.Server, id string) nodeRouteReview {
	t.Helper()
	code, data := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/preview", map[string]any{"engine": "xray", "service_id": "telegram", "scope": map[string]any{"mode": "selected", "sources": []string{"192.168.1.40/32"}}}, componentRecoveryToken, s.URL)
	var v struct {
		Ready  bool            `json:"ready"`
		Review nodeRouteReview `json:"review"`
		Plan   dataplane.Plan  `json:"transaction"`
	}
	if code != 200 || json.Unmarshal(data, &v) != nil || !v.Ready || v.Review.Engine != "xray" || v.Review.Token == "" || len(v.Plan.Routes) != 1 || v.Plan.Routes[0].Resolved != "xray:"+id || v.Plan.NetworkProfileID != "wan-0123456789ab" {
		t.Fatalf("Xray review failed: %d %s", code, data)
	}
	return v.Review
}

func xrayApplyBody(review nodeRouteReview) map[string]any {
	body := nodeApplyBody(review)
	body["engine"] = "xray"
	return body
}

func TestXrayNodeRouteHTTPApplyKeepsEngineAndScope(t *testing.T) {
	a, id, sing, xray := xrayRouteFixture(t, true)
	before := a.Store.Get()
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	review := previewXrayHTTP(t, s, id)
	body := xrayApplyBody(review)
	code, data := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/apply", body, componentRecoveryToken, s.URL)
	if code != 200 {
		t.Fatal(code, string(data))
	}
	after := a.Store.Get()
	if after.AppliedServices["telegram"].Route != "xray:"+id || !slices.Equal(after.AppliedServices["telegram"].Sources, []string{"192.168.1.40/32"}) || !reflect.DeepEqual(before.Services["youtube"], after.Services["youtube"]) || len(sing.calls) != 0 || !slices.Contains(xray.calls, "health") || !slices.Contains(xray.calls, "commit") {
		t.Fatal("engine/scope/drafts changed", after, sing.calls, xray.calls)
	}
	committed, present, err := a.Dataplane.Committed()
	if err != nil || !present || committed.Routes[0].Resolved != "xray:"+id || !committed.RequiresNetworkProof() {
		t.Fatal("Xray proof lost at commit", committed, err)
	}
	calls := len(xray.calls)
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/apply", body, componentRecoveryToken, s.URL); code != 409 || len(xray.calls) != calls {
		t.Fatal("spent review replayed", code)
	}
}

func TestXrayNodeRouteHTTPRefusesChangedBindingsAndRollsBack(t *testing.T) {
	for _, changed := range []string{"engine", "history-gate", "health", "wan-after-activate"} {
		t.Run(changed, func(t *testing.T) {
			a, id, sing, xray := xrayRouteFixture(t, true)
			before := a.Store.Get()
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			review := previewXrayHTTP(t, s, id)
			body := xrayApplyBody(review)
			switch changed {
			case "engine":
				body["engine"] = "sing-box"
			case "history-gate":
				a.NodeHistoryWriteGuard = func(context.Context, int) error { return errors.New("downgrade admission revoked") }
			case "health":
				xray.after = func(phase string) error {
					if phase == "health" {
						return errors.New("independent live failure")
					}
					return nil
				}
			case "wan-after-activate":
				xray.after = func(phase string) error {
					if phase == "activate" {
						a.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
						a.Dataplane.FreshProfile = a.FreshProfile
					}
					return nil
				}
			}
			code, _ := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/apply", body, componentRecoveryToken, s.URL)
			if code == 200 || !reflect.DeepEqual(before, a.Store.Get()) || len(sing.calls) != 0 {
				t.Fatal("changed authority committed or fell back", code, xray.calls)
			}
			if changed == "health" || changed == "wan-after-activate" {
				if !slices.Contains(xray.calls, "rollback") || slices.Contains(xray.calls, "commit") {
					t.Fatal("rollback missing", xray.calls)
				}
			} else if len(xray.calls) != 0 {
				t.Fatal("early refusal performed effects", xray.calls)
			}
		})
	}
}

func TestXrayNodeRouteHTTPDoesNotBorrowSingBoxProof(t *testing.T) {
	a, id, sing, xray := xrayRouteFixture(t, false)
	before := a.Store.Get()
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	code, _ := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/preview", map[string]any{"engine": "xray", "service_id": "telegram"}, componentRecoveryToken, s.URL)
	if code == 200 || !reflect.DeepEqual(before, a.Store.Get()) || len(sing.calls)+len(xray.calls) != 0 {
		t.Fatal("Sing-box proof authorized Xray", code)
	}
}

func TestDurableXrayNodeApplyRetainsEngineAndDoesNotReplay(t *testing.T) {
	a, id, sing, xray := xrayRouteFixture(t, true)
	initReconcilerFixture(t, a, time.Now())
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	review := previewXrayHTTP(t, s, id)
	body := xrayApplyBody(review)
	body["idempotency_key"] = "durable-xray-reviewed-route"
	code, data := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/apply", body, componentRecoveryToken, s.URL)
	var v struct {
		Job nodeCheckJob `json:"job"`
	}
	if code != 202 || json.Unmarshal(data, &v) != nil {
		t.Fatal(code, string(data))
	}
	job := durableJobAt(t, a, v.Job.ID)
	if job.Request.NodeApply.Engine != "xray" || len(xray.calls) != 0 {
		t.Fatal("durable engine lost", job)
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	job = durableJobAt(t, a, v.Job.ID)
	if job.State != "completed" || a.Store.Get().AppliedServices["telegram"].Route != "xray:"+id || len(sing.calls) != 0 {
		t.Fatal(job, xray.calls)
	}
	raw, err := os.ReadFile(a.reconciler.path)
	if err != nil || strings.Contains(string(raw), review.Token) || !strings.Contains(string(raw), `"engine":"xray"`) {
		t.Fatal("durable receipt lost engine or leaked token", err)
	}
	calls := len(xray.calls)
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/apply", body, componentRecoveryToken, s.URL); code != 202 || len(xray.calls) != calls {
		t.Fatal("durable retry replayed", code)
	}
}

func TestXrayNodeSelectorRequiresScopedAdapterAndIndependentProbe(t *testing.T) {
	a, id, _, _ := xrayRouteFixture(t, true)
	base := []routecatalog.Option{{ID: "sing-box", Installed: true}, {ID: "xray", Installed: true}}
	configs := engineconfig.New(t.TempDir(), t.TempDir())
	generic, err := dataplane.NewProxyTunnelAdapter("xray", configs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(t.TempDir())
	if err := manager.Register(generic); err != nil {
		t.Fatal(err)
	}
	a.Dataplane = manager
	if manager.XrayNodeRouteCapable() || routecatalog.ValidWithOptions("xray:"+id, a.appendNodeRouteOptions(context.Background(), base)) {
		t.Fatal("generic Xray became a scoped registry executor")
	}
	materialize := func(context.Context, []dataplane.NodeRouteRequest, string, time.Time) (dataplane.NodeRouteMaterial, error) {
		return dataplane.NodeRouteMaterial{}, errors.New("never called by selector")
	}
	scoped, err := dataplane.NewScopedXrayTunnelAdapter(configs, t.TempDir(), materialize)
	if err != nil {
		t.Fatal(err)
	}
	manager = dataplane.New(t.TempDir())
	if err = manager.Register(scoped); err != nil {
		t.Fatal(err)
	}
	a.Dataplane = manager
	if manager.XrayNodeRouteCapable() || routecatalog.ValidWithOptions("xray:"+id, a.appendNodeRouteOptions(context.Background(), base)) {
		t.Fatal("missing LAN observer granted selector permission")
	}
	scoped.NodeTUNProbe = func(context.Context, dataplane.NodeTUNRequest) (dataplane.NodeTUNObservation, error) {
		return dataplane.NodeTUNObservation{}, errors.New("not invoked by selector")
	}
	if !manager.XrayNodeRouteCapable() || !routecatalog.ValidForServiceWithOptions("xray:"+id, "telegram", a.appendNodeRouteOptions(context.Background(), base)) {
		t.Fatal("exact Xray proof/capability not exposed")
	}
	a.NodeHistoryWriteGuard = nil
	if routecatalog.ValidWithOptions("xray:"+id, a.appendNodeRouteOptions(context.Background(), base)) {
		t.Fatal("missing downgrade guard exposed route")
	}
}
