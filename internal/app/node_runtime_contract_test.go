package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func TestNodeCheckPersistsRuntimeContract(t *testing.T) {
	a, checker, initial := nodeCheckContractFixture(t)
	checker.result.RuntimeContract = providerprofile.SingBoxRealityUTLSContract
	response := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, nodeCheckContractRequest(context.Background(), initial.Nodes[0].ID))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"runtime_contract":"`+providerprofile.SingBoxRealityUTLSContract+`"`) {
		t.Fatalf("runtime contract missing from response: status=%d", response.Code)
	}
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || len(snapshot.Nodes[0].Health.History) != 1 || snapshot.Nodes[0].Health.History[0].RuntimeContract != providerprofile.SingBoxRealityUTLSContract {
		t.Fatal("exact check runtime contract lost before materializer", err)
	}
}
