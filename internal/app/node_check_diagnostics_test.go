package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestDisabledServiceNodeCheckReportsRealResourceRefusalBeforeRuntime(t *testing.T) {
	a, ids := newNodeJobTest(t, 1)
	state := a.Store.Get().Services["telegram"]
	state.Enabled = false
	if err := a.Store.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeRuntime
	})
	beforeConfig := a.Store.Get()
	beforeNodes, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	service := a.Catalog.Services[0]
	result, _, err := a.checkAndRecordNode(context.Background(), ids[0], service, "", 0)
	if !errors.Is(err, dataplane.ErrNodeResourceDenied) || calls != 0 {
		t.Fatal("disabled service reached runtime or lost typed refusal", err, calls)
	}
	// Both detached legacy checks and durable jobs publish the same safe cause.
	legacy := a.runNodeCheckItem(context.Background(), "service", ids[0], service, "", nil)
	durable := nodeCheckItemFromResult(ids[0], "", result, err)
	for _, item := range []nodeCheckItem{legacy, durable} {
		if item.ErrorCode != "node-resource-refused" || item.Verdict != "INCONCLUSIVE" || item.Available || !strings.Contains(item.Message, "исключения") {
			t.Fatal("resource denial became generic or positive", item)
		}
	}
	afterNodes, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || calls != 0 || !reflect.DeepEqual(beforeConfig, a.Store.Get()) || !reflect.DeepEqual(beforeNodes, afterNodes) {
		t.Fatal("diagnostic changed consent, node history or ran checker", err, calls)
	}
}

func TestNodeCheckTypedDiagnosticsNeverPublishRawErrorMaterial(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{dataplane.ErrNodeResourceDenied, "node-resource-refused"},
		{dataplane.ErrExactNodeRuntime, "node-runtime-unavailable"},
		{dataplane.ErrExactNodeUnsupported, "node-runtime-unsupported"},
		{dataplane.ErrExactNodeUnavailable, "node-checker-unavailable"},
		{errors.New("unclassified"), "node-check-unconfirmed"},
	} {
		private := "vless://credential@private-host.invalid /private/runtime/path --secret-arg"
		err := fmt.Errorf("%s: %w", private, tc.err)
		item := nodeCheckItemFromResult("test-node", "", dataplane.NodeCheckResult{}, err)
		raw, marshalErr := json.Marshal(item)
		if marshalErr != nil || item.ErrorCode != tc.code || item.Verdict != "INCONCLUSIVE" || item.Available || strings.Contains(string(raw), private) || strings.Contains(string(raw), "credential") || strings.Contains(string(raw), "private-host") || strings.Contains(string(raw), "--secret") {
			t.Fatal("unsafe or incorrect public diagnostic", item, marshalErr)
		}
		if tc.code != "node-check-unconfirmed" && strings.Contains(item.Message, "обновления списка") {
			t.Fatal("typed error fell back to unrelated catalogue advice", item)
		}
	}
}
