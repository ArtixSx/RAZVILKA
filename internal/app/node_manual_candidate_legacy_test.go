package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func postLegacyCandidateFetch(t *testing.T, a *App) uint64 {
	t.Helper()
	raw, _ := json.Marshal(nodeCheckJobRequest{Mode: "service", ServiceID: "telegram", Confirm: "FETCH_AND_CHECK_NODES", Feed: &providerfeed.Request{PresetID: "kort0881-ru-sni", Limit: 12}})
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/node-checks", strings.NewReader(string(raw))))
	if w.Code != http.StatusAccepted {
		t.Fatal(w.Code, w.Body.String())
	}
	var response struct{ Job nodeCheckJob }
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Job.ID == 0 {
		t.Fatal("original fetch job missing")
	}
	return response.Job.ID
}

func TestLegacyManualCandidateFetchDisabledServiceUsesExactReturnedSelection(t *testing.T) {
	a, ids := newNodeJobTest(t, 2)
	a.NodeFeeds = providerfeed.New(a.Nodes)
	state := a.Store.Get().Services["telegram"]
	state.Enabled = false
	if err := a.Store.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	a.nodeChecks.fetchSource = func(context.Context, nodeCheckJobRequest) (providerfeed.Result, error) {
		return providerfeed.Result{SourceID: "manual", NodeIDs: ids[:1], Imported: 1}, nil
	}
	checked := make(chan string, 2)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked <- r.NodeID
		return autofallbackResult(r, true), nil
	})
	id := postLegacyCandidateFetch(t, a)
	job := joinNodeJob(t, a)
	if job.ID != id || job.State != "completed" || job.Completed != 1 || job.Passed != 1 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("same-job diagnostic did not complete or activated service", job)
	}
	if got := <-checked; got != ids[0] {
		t.Fatal("checked outside fetched selection", got)
	}
	select {
	case <-checked:
		t.Fatal("unrelated candidate was checked")
	default:
	}
}

func TestLegacyManualCandidateFetchChangesBeforeChecksRevokeOriginalIntent(t *testing.T) {
	for _, change := range []string{"revision", "definition", "stop", "excluded"} {
		t.Run(change, func(t *testing.T) {
			a, ids := newNodeJobTest(t, 1)
			a.NodeFeeds = providerfeed.New(a.Nodes)
			if err := a.Store.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			if err := a.Store.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			state := a.Store.Get().Services["telegram"]
			state.Enabled = false
			if err := a.Store.UpdateService("telegram", state); err != nil {
				t.Fatal(err)
			}
			if change == "excluded" {
				manual := []config.ResourceMatch{{Kind: "service", Value: "telegram"}}
				if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
			}
			beforeNodes, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			a.nodeChecks.fetchSource = func(context.Context, nodeCheckJobRequest) (providerfeed.Result, error) {
				switch change {
				case "revision":
					if err := a.Store.SetSafeMode(true); err != nil {
						t.Error(err)
					}
				case "definition":
					a.Catalog.Services[0].ProbeURL = "https://changed.invalid/"
				case "stop":
					if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "direct"}, a.Store.Get().Revision); err != nil {
						t.Error(err)
					}
				}
				return providerfeed.Result{SourceID: "manual", NodeIDs: ids, Imported: 1}, nil
			}
			calls := make(chan struct{}, 1)
			a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls <- struct{}{}
				return dataplane.NodeCheckResult{}, nil
			})
			id := postLegacyCandidateFetch(t, a)
			job := joinNodeJob(t, a)
			afterNodes, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if job.ID != id || job.Passed != 0 || afterNodes.Generation != beforeNodes.Generation {
				t.Fatal("changed intent produced proof or replaced job identity", job)
			}
			select {
			case <-calls:
				t.Fatal("checker ran after source intent revoked")
			default:
			}
			if change == "stop" && !a.Store.Get().ServiceControl.Stopped {
				t.Fatal("candidate check resumed stopped routes")
			}
			if change == "excluded" && (len(job.Results) != 1 || job.Results[0].ErrorCode != "node-resource-refused") {
				t.Fatal("exclusion lost its exact diagnostic", job)
			}
		})
	}
}
