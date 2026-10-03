package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type engineNodeFixture struct {
	engine string
	calls  int
	err    error
	alter  func(*dataplane.NodeCheckResult)
}

func (f *engineNodeFixture) EngineID() string            { return f.engine }
func (*engineNodeFixture) Recover(context.Context) error { return nil }
func (f *engineNodeFixture) Check(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	f.calls++
	r := bulkTestResult(q)
	r.ProbeID += "-" + f.engine
	r.RoutePathID = f.engine + ":" + q.NodeID
	r = modeledNodeServiceProof(r, f.engine)
	if f.alter != nil {
		f.alter(&r)
	}
	return r, f.err
}

func engineNodeHTTPFixture(t *testing.T) (*App, *engineNodeFixture, *engineNodeFixture, string) {
	t.Helper()
	a, _, initial := nodeCheckContractFixture(t)
	a.Security, _ = security.NewGate(componentRecoveryToken)
	sing := &engineNodeFixture{engine: "sing-box"}
	xray := &engineNodeFixture{engine: "xray"}
	a.NodeChecker = sing
	a.NodeCheckers = map[string]dataplane.NodeChecker{"sing-box": sing, "xray": xray}
	a.NodeHistoryWriteGuard = func(c context.Context, version int) error {
		if version != nodestore.ExactHistoryReadVersion {
			return errors.New("wrong read version")
		}
		return c.Err()
	}
	return a, sing, xray, initial.Nodes[0].ID
}

func postEngineNode(t *testing.T, s *httptest.Server, id, engine string) (int, []byte) {
	t.Helper()
	return componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/check", map[string]any{"engine": engine, "service_id": "discord", "confirm": "CHECK_NODE"}, componentRecoveryToken, s.URL)
}

func TestNodeEngineHTTPKeepsDistinctExactHistoryAndReadCapability(t *testing.T) {
	a, sing, xray, id := engineNodeHTTPFixture(t)
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	for _, engine := range []string{"sing-box", "xray"} {
		if code, data := postEngineNode(t, s, id, engine); code != 200 || !bytes.Contains(data, []byte(engine+":"+id)) {
			t.Fatalf("%s: %d %s", engine, code, data)
		}
	}
	if sing.calls != 1 || xray.calls != 1 {
		t.Fatal("wrong engine dispatch", sing.calls, xray.calls)
	}
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nodes[0].Health.History) != 2 {
		t.Fatal("history overwritten", snapshot.Nodes[0].Health.History)
	}
	for _, engine := range []string{"sing-box", "xray"} {
		proof, err := a.Nodes.ResolveRouteForEngine(context.Background(), engine, id, "discord", "wan-0123456789ab", "", time.Time{}, time.Now())
		if err != nil || proof.Route != engine+":"+id {
			t.Fatal("engine proof lost", engine, proof, err)
		}
	}
	version, err := a.Nodes.RequiredHistoryReadVersion(context.Background())
	if err != nil || version != 2 {
		t.Fatal("downgrade capability hidden", version, err)
	}
	backup, err := a.Nodes.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	version, err = nodestore.RequiredPrivateHistoryReadVersion(backup)
	if err != nil || version != 2 {
		t.Fatal("backup lost read capability", version, err)
	}
}

func TestNodeEngineHTTPRejectsWrongProofWithoutRecordOrFallback(t *testing.T) {
	for _, wrong := range []string{"path", "node", "service", "network", "evidence-engine", "evidence-route", "expected-route", "observed-route", "evidence-service", "evidence-network", "missing-evidence", "direct-leak", "unavailable-diagnostic-engine"} {
		t.Run(wrong, func(t *testing.T) {
			a, sing, xray, id := engineNodeHTTPFixture(t)
			before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			xray.alter = func(r *dataplane.NodeCheckResult) {
				switch wrong {
				case "path":
					r.RoutePathID = "sing-box:" + id
				case "node":
					r.NodeID = "node-other"
				case "service":
					r.ServiceID = "telegram"
				case "network":
					r.NetworkProfile = "wan-other"
				case "evidence-engine":
					r.Evidence.Engine = "sing-box"
				case "evidence-route":
					r.Evidence.RoutePathID = "sing-box:" + id
				case "expected-route":
					r.Evidence.ExpectedRoutePathID = "sing-box:" + id
				case "observed-route":
					r.Evidence.ObservedRoutePathID = "sing-box:" + id
				case "evidence-service":
					r.Evidence.Service = "telegram"
				case "evidence-network":
					r.Evidence.NetworkProfile = "wan-other"
				case "missing-evidence":
					r.Evidence.SchemaVersion = 0
				case "direct-leak":
					r.DirectLeak = true
				case "unavailable-diagnostic-engine":
					r.Available = false
					r.Evidence.Engine = "sing-box"
				}
			}
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			if code, _ := postEngineNode(t, s, id, "xray"); code != 503 {
				t.Fatal("wrong proof admitted", code)
			}
			after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if after.Generation != before.Generation || len(after.Nodes[0].Health.History) != 0 || len(a.nodeChecks.measurements.Snapshot(time.Now())) != 0 || sing.calls != 0 || xray.calls != 1 {
				t.Fatal("wrong proof recorded or retried", sing.calls, xray.calls, after.Generation, before.Generation)
			}
		})
	}
}

func TestNodeEngineHTTPEarlyErrorsAndHistoryGateDoNotObserve(t *testing.T) {
	for _, failure := range []string{"unsupported", "runtime", "busy", "network", "missing-history-gate", "retained-reader-one", "revoked-history-gate", "network-after-check"} {
		t.Run(failure, func(t *testing.T) {
			a, sing, xray, id := engineNodeHTTPFixture(t)
			before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			want := 503
			calls := 1
			switch failure {
			case "unsupported":
				xray.err = dataplane.ErrExactNodeUnsupported
				want = 409
			case "runtime":
				xray.err = dataplane.ErrExactNodeRuntime
			case "busy":
				xray.err = dataplane.ErrExactNodeBusy
				want = 409
			case "network":
				xray.err = dataplane.ErrExactNodeNetworkChanged
				want = 409
			case "missing-history-gate":
				a.NodeHistoryWriteGuard = nil
				calls = 0
			case "retained-reader-one":
				a.NodeHistoryWriteGuard = func(context.Context, int) error { return updatecheck.ErrNodeHistoryAdmission }
				calls = 0
			case "revoked-history-gate":
				n := 0
				a.NodeHistoryWriteGuard = func(context.Context, int) error {
					n++
					if n > 1 {
						return dataplane.ErrExactNodeUnavailable
					}
					return nil
				}
			case "network-after-check":
				xray.alter = func(*dataplane.NodeCheckResult) {
					a.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
				}
				want = 409
			}
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			if code, _ := postEngineNode(t, s, id, "xray"); code != want {
				t.Fatal("wrong error status", failure, code, want)
			}
			after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if after.Generation != before.Generation || len(a.nodeChecks.measurements.Snapshot(time.Now())) != 0 || sing.calls != 0 || xray.calls != calls {
				t.Fatal("early error recorded/fallback", failure, sing.calls, xray.calls)
			}
		})
	}
}

func TestNodeEngineHTTPStrictEngineAndAuthentication(t *testing.T) {
	a, sing, xray, id := engineNodeHTTPFixture(t)
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	for _, engine := range []string{"Xray", "xray ", "auto", "xray:node-other"} {
		if code, _ := postEngineNode(t, s, id, engine); code != 400 {
			t.Fatal("engine widened", engine, code)
		}
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/check", map[string]any{"engine": "xray", "service_id": "discord", "confirm": "CHECK_NODE"}, "", s.URL); code != 401 {
		t.Fatal("auth bypass", code)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/nodes/"+id+"/check", map[string]any{"engine": "xray", "service_id": "discord", "confirm": "CHECK_NODE"}, componentRecoveryToken, "https://foreign.example"); code != 403 {
		t.Fatal("Origin bypass", code)
	}
	if sing.calls != 0 || xray.calls != 0 {
		t.Fatal("invalid request observed")
	}
	// Legacy clients explicitly retain their default fixed Sing-box view.
	if code, _ := postEngineNode(t, s, id, ""); code != 200 || sing.calls != 1 || xray.calls != 0 {
		t.Fatal("legacy default changed", code)
	}
}

// Keep a real network request in this fixture to verify strict JSON through
// security middleware; engine values never configure executables or endpoints.
func TestNodeEngineHTTPRejectsInjectedExecutor(t *testing.T) {
	a, sing, xray, id := engineNodeHTTPFixture(t)
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	data, _ := json.Marshal(map[string]any{"engine": "xray", "service_id": "discord", "confirm": "CHECK_NODE", "binary": "/tmp/foreign"})
	r, _ := http.NewRequest("POST", s.URL+"/api/v1/nodes/"+id+"/check", strings.NewReader(string(data)))
	r.Header.Set("Authorization", "Bearer "+componentRecoveryToken)
	r.Header.Set("Origin", s.URL)
	r.Header.Set("Content-Type", "application/json")
	res, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 400 || sing.calls != 0 || xray.calls != 0 {
		t.Fatal("executor from HTTP accepted", res.StatusCode)
	}
}
