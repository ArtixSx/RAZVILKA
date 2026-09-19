package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func nodeCheckContractFixture(t *testing.T) (*App, *fakeNodeChecker, nodestore.Snapshot) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	initial, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@private-node.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id, now := initial.Nodes[0].ID, time.Now().UTC()
	checker := &fakeNodeChecker{result: dataplane.NodeCheckResult{
		SchemaVersion: 1, ProbeID: "node-check-contract", NodeID: id, ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(time.Hour), LatencyMS: 1000, HTTPStatus: 200,
		TestLevel: "service", Stage: "service_ip", Verdict: evidence.VerdictError, ErrorCode: "node-service-ip-path-failed",
		Message: "Узел не подтвердил доступ к сервису по IP-адресу, необходимый для маршрута устройств.",
		Stages:  []dataplane.NodeCheckStage{{ID: "service", Status: "passed"}, {ID: "service_ip", Status: "failed"}},
	}}
	a := &App{Nodes: store, NodeChecker: checker, FreshProfile: stableNodeProfile, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "discord", Name: "Discord", ProbeURL: "https://discord.com/"}}}}
	return a, checker, initial
}

func nodeCheckContractRequest(ctx context.Context, id string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+id+"/check", strings.NewReader(`{"service_id":"discord","confirm":"CHECK_NODE"}`)).WithContext(ctx)
}

func TestNodeIPFailureEndpointPreservesReportAndRevokesProof(t *testing.T) {
	for _, longMessage := range []bool{false, true} {
		name := "production-message"
		if longMessage {
			name = "localized-message-over-240-bytes"
		}
		t.Run(name, func(t *testing.T) {
			a, checker, initial := nodeCheckContractFixture(t)
			id, failed := initial.Nodes[0].ID, checker.result
			if longMessage {
				checker.result.Message += " Контроль имени прошёл успешно, но проверка всех IP-адресов сервиса пока не завершена."
				if len(checker.result.Message) <= 240 {
					t.Fatal("fixture must exercise the former byte limit")
				}
			}
			pass := nodestore.CheckRecord{ProbeID: "node-check-earlier-pass", ServiceID: failed.ServiceID, NetworkProfile: failed.NetworkProfile, RoutePathID: failed.RoutePathID,
				TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: failed.StartedAt.Add(-time.Second), ExpiresAt: failed.ExpiresAt}
			before, err := a.Nodes.RecordCheck(context.Background(), id, pass, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(response, nodeCheckContractRequest(context.Background(), id))
			var body struct {
				OK                   bool                      `json:"ok"`
				Result               dataplane.NodeCheckResult `json:"result"`
				WorkingRoutesChanged bool                      `json:"working_routes_changed"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatalf("IP-path refusal was replaced by an API error: %d %s", response.Code, response.Body.String())
			}
			if body.OK || body.WorkingRoutesChanged || body.Result.Available || body.Result.Stage != "service_ip" || body.Result.ErrorCode != failed.ErrorCode || body.Result.Message != checker.result.Message || len(body.Result.Stages) != 2 {
				t.Fatalf("IP-path report lost its failure or acquired authority: %+v", body)
			}
			after, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil || after.Generation != before.Generation+1 || after.Nodes[0].Health.State != "unavailable" || after.Nodes[0].Health.ErrorCode != failed.ErrorCode || len(after.Nodes[0].Health.History) != 2 || after.Nodes[0].Health.History[0].Stage != "service_ip" {
				t.Fatalf("IP-path failure was not recorded: %+v err=%v", after, err)
			}
			services, err := a.Nodes.RouteServices(context.Background(), id, failed.NetworkProfile, time.Now())
			if err != nil || len(services) != 0 {
				t.Fatalf("failed IP path left an earlier PASS selectable: %v %v", services, err)
			}
			for _, secret := range []string{"private-node.example", "123e4567", "vless://"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("result exposed private node material")
				}
			}
		})
	}
}

func TestNodeInterruptedEndpointReturnsStructuredUnrecordedResult(t *testing.T) {
	for _, tc := range []struct {
		name, stage, code, resultCode string
		err                           error
		status                        int
	}{
		{"deadline", "deadline", "NODE_CHECK_DEADLINE", "node-check-deadline", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"canceled", "canceled", "NODE_CHECK_CANCELED", "node-check-canceled", context.Canceled, http.StatusRequestTimeout},
		{"cleanup-beats-deadline", "cleanup", "NODE_CLEANUP_REQUIRED", "node-cleanup-failed", context.DeadlineExceeded, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, checker, before := nodeCheckContractFixture(t)
			checker.result.Stage, checker.result.ErrorCode, checker.err = tc.stage, tc.resultCode, tc.err
			response := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(response, nodeCheckContractRequest(context.Background(), before.Nodes[0].ID))
			var body struct {
				OK                   bool                      `json:"ok"`
				Code                 string                    `json:"code"`
				Recorded             *bool                     `json:"recorded"`
				Result               dataplane.NodeCheckResult `json:"result"`
				WorkingRoutesChanged bool                      `json:"working_routes_changed"`
			}
			if response.Code != tc.status || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Code != tc.code || body.Recorded == nil || *body.Recorded {
				t.Fatalf("interrupted check lost structured diagnosis: %d %s", response.Code, response.Body.String())
			}
			if body.OK || body.WorkingRoutesChanged || body.Result.Available || body.Result.Verdict == evidence.VerdictPass || body.Result.ErrorCode != tc.resultCode || body.Result.Stage != tc.stage || body.Result.NodeID != before.Nodes[0].ID || len(body.Result.Stages) != 2 {
				t.Fatalf("interrupted result lost identity or gained authority: %+v", body)
			}
			after, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil || after.Generation != before.Generation || len(after.Nodes[0].Health.History) != 0 {
				t.Fatalf("interrupted result was recorded without valid context: %+v %v", after, err)
			}
		})
	}
}

func TestNodeCancellationAfterCheckIsNotReportedAsWANChange(t *testing.T) {
	a, checker, before := nodeCheckContractFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.result.Available, checker.result.Verdict, checker.result.Stage = true, evidence.VerdictPass, "service"
	checker.result.ErrorCode, checker.result.EgressIP = "", "8.8.8.8"
	checker.onCheck = cancel
	response := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, nodeCheckContractRequest(ctx, before.Nodes[0].ID))
	var body struct {
		Code   string                    `json:"code"`
		Result dataplane.NodeCheckResult `json:"result"`
	}
	if response.Code != http.StatusRequestTimeout || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Code != "NODE_CHECK_CANCELED" || body.Result.Stage != "canceled" || body.Result.Available || body.Result.EgressIP != "" || body.Result.Verdict == evidence.VerdictPass {
		t.Fatalf("post-check cancellation was masked or exposed PASS: %d %s", response.Code, response.Body.String())
	}
	after, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || after.Generation != before.Generation || len(after.Nodes[0].Health.History) != 0 || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("canceled check changed history: %+v %v", after, err)
	}
}
