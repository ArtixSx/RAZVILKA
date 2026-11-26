package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestNodeEgressDiagnosticEndpointRetainsSafeExplanationWithoutNewHistoryFormat(t *testing.T) {
	for _, controlUnavailable := range []bool{false, true} {
		a, checker, initial := nodeCheckContractFixture(t)
		checker.result.TestLevel, checker.result.Stage, checker.result.ErrorCode = "protocol", "egress", "node-egress-failed"
		checker.result.HTTPStatus, checker.result.DirectControl, checker.result.ProxyEgressError = 0, "measured", "socks_connect"
		checker.result.Message = "Точный выход через узел не подтвердился. Проверочный запрос через SOCKS не установил соединение."
		if controlUnavailable {
			checker.result.TestLevel, checker.result.ErrorCode, checker.result.DirectControl = "egress", "node-egress-control-unavailable", "unavailable"
			checker.result.Verdict, checker.result.DirectEgressError = evidence.VerdictInconclusive, "certificate"
		}
		response := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(response, nodeCheckContractRequest(context.Background(), initial.Nodes[0].ID))
		var body struct {
			OK     bool                      `json:"ok"`
			Result dataplane.NodeCheckResult `json:"result"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.OK || body.Result.Available || body.Result.ErrorCode != checker.result.ErrorCode {
			t.Fatalf("diagnostic changed failure response: %d %s", response.Code, response.Body.String())
		}
		list := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil))
		var snapshot struct {
			Nodes []nodestore.Node `json:"nodes"`
		}
		if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &snapshot) != nil || len(snapshot.Nodes) != 1 || len(snapshot.Nodes[0].Health.History) != 1 {
			t.Fatal("diagnostic history not returned", list.Code)
		}
		got := snapshot.Nodes[0].Health.History[0]
		if got.Message != checker.result.Message || got.ErrorCode != checker.result.ErrorCode || got.State != "unavailable" {
			t.Fatalf("check-and-record discarded diagnostic: %+v", got)
		}
		if reader, err := a.Nodes.RequiredHistoryReadVersion(context.Background()); err != nil || reader != 1 {
			t.Fatal("explanation changed legacy Sing-box reader requirement", reader, err)
		}
		if strings.Contains(list.Body.String(), "egress_error") {
			t.Fatal("diagnostic added fields unreadable by retained strict readers")
		}
		services, err := a.Nodes.RouteServices(context.Background(), initial.Nodes[0].ID, checker.result.NetworkProfile, time.Now())
		if err != nil || len(services) != 0 {
			t.Fatal("diagnostic granted route proof", services, err)
		}
		for _, secret := range []string{"private-node.example", "123e4567", "vless://"} {
			if strings.Contains(response.Body.String()+list.Body.String(), secret) {
				t.Fatal("diagnostic exposed private material")
			}
		}
	}
}
