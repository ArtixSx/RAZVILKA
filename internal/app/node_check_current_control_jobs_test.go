package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNodeCheckCurrentKeepsLastCheckWhenNewerStopOrResumeExists(t *testing.T) {
	for _, kind := range []string{"stop", "resume"} {
		for _, state := range []string{"queued", "running", "completed", "failed", "canceled"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				a, request := durableNodeFixture(t, 1)
				checkID := enqueueNodeFixture(t, a, request)
				a.runDurableServiceJob(context.Background(), time.Now())
				controlID := checkID + 1
				a.reconciler.doc.Jobs = append(a.reconciler.doc.Jobs, durableServiceJob{
					ID: controlID, Request: serviceControlJobRequest{Kind: kind},
					State: state, CreatedAt: time.Now().Add(time.Minute),
				})
				w := httptest.NewRecorder()
				a.nodeCheckJobCurrent(w, httptest.NewRequest(http.MethodGet, "/api/v1/node-checks/current", nil))
				var response struct {
					Job         *nodeCheckJob   `json:"job"`
					DurableJobs []*nodeCheckJob `json:"durable_jobs"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
					t.Fatalf("current check response: %d %s", w.Code, w.Body.String())
				}
				if response.Job == nil || response.Job.ID != checkID || response.Job.Mode != "service" || response.Job.State != "completed" || response.Job.Completed != 1 {
					t.Fatalf("control operation replaced the completed node check: %+v", response.Job)
				}
				if len(response.DurableJobs) != 2 || response.DurableJobs[1].ID != controlID || response.DurableJobs[1].Mode != "service-"+kind || response.DurableJobs[1].State != state {
					t.Fatalf("control operation disappeared from durable history: %+v", response.DurableJobs)
				}
				if current := a.serviceControlMemory()["job"].(*nodeCheckJob); current.ID != controlID {
					t.Fatalf("service-control current lost the control operation: %+v", current)
				}
				// After restart only the durable records remain; the latest check
				// must still win over a newer control operation.
				a.nodeChecks.job = nil
				w = httptest.NewRecorder()
				a.nodeCheckJobCurrent(w, httptest.NewRequest(http.MethodGet, "/api/v1/node-checks/current", nil))
				if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Job == nil || response.Job.ID != checkID || response.Job.State != "completed" {
					t.Fatal("durable-only node view lost the last check", w.Body.String())
				}
			})
		}
	}
}

func TestNodeCheckCurrentWithoutChecksDoesNotPresentControlOperation(t *testing.T) {
	a, _ := durableNodeFixture(t, 1)
	a.reconciler.doc.Jobs = []durableServiceJob{{ID: 7, Request: serviceControlJobRequest{Kind: "stop"}, State: "failed", CreatedAt: time.Now()}}
	view := a.nodeCheckCurrentView()
	if current, _ := view["job"].(*nodeCheckJob); current != nil {
		t.Fatalf("Stop was presented as a never-started node check: %+v", current)
	}
	if jobs := view["durable_jobs"].([]*nodeCheckJob); len(jobs) != 1 || jobs[0].Mode != "service-stop" {
		t.Fatal("Stop disappeared from durable history")
	}
}
