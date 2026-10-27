package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func serviceDiagnosticResult(q dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	now := time.Now().UTC()
	return dataplane.NodeCheckResult{NodeID: q.NodeID, ServiceID: q.Service.ID, NetworkProfile: q.NetworkProfile,
		RoutePathID: "xray:" + q.NodeID, ProbeID: "node-check-0123456789abcdef01234567", StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		Stage: "egress", DirectControl: "measured", CleanupStatus: dataplane.NodeCleanupVerified, TestLevel: "protocol", Verdict: evidence.VerdictError, ErrorCode: "node-egress-failed", Message: "Измерение не подтвердилось."}
}

func TestServiceJobDTOKeepsXrayFailureAndIndependentCleanup(t *testing.T) {
	a, _ := newNodeJobTest(t, 1)
	id := importXHTTPNode(t, a)
	useQuotaEngines(t, a, id, "sing-box", "xray")
	var original dataplane.NodeCheckResult
	a.NodeCheckers["xray"] = jobNodeChecker(func(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		original = serviceDiagnosticResult(q)
		return original, nil
	})
	if w := postNodeJob(t, a, []string{id}, "service"); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	job := joinNodeJob(t, a)
	if len(job.Results) != 1 {
		t.Fatal(job)
	}
	item := job.Results[0]
	if item.Engine != "xray" || item.Stage != "egress" || item.DirectControl != "measured" || item.ProbeID != original.ProbeID || !item.CleanupVerified || item.CleanupStatus != dataplane.NodeCleanupVerified || item.Available || item.ConnectivityReady || item.ErrorCode != "node-egress-failed" || !item.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("diagnostic lost or failure promoted", item)
	}
	// The screening/durable projection uses the same binding and does not create
	// connectivity readiness from a service observation.
	durable := nodeCheckItemFromResult(id, original.NetworkProfile, original, nil, "xray")
	if durable.Engine != item.Engine || durable.Stage != item.Stage || durable.CleanupStatus != item.CleanupStatus || durable.ConnectivityReady {
		t.Fatal("mapping diverged", durable)
	}
	encoded, _ := json.Marshal(job)
	for _, key := range []string{`"engine":"xray"`, `"stage":"egress"`, `"cleanup_status":"verified"`} {
		if !strings.Contains(string(encoded), key) {
			t.Fatal("current job JSON omitted diagnostic", string(encoded))
		}
	}
}

func TestServiceDTODoesNotInferCleanupOrLeakUnknownMetadata(t *testing.T) {
	id := "node-" + strings.Repeat("1", 64)
	q := dataplane.NodeCheckRequest{NodeID: id, NetworkProfile: "wan-0123456789ab"}
	result := serviceDiagnosticResult(q)
	result.CleanupStatus = ""
	legacy := nodeCheckItemFromResult(id, q.NetworkProfile, result, nil, "xray")
	if legacy.CleanupVerified || legacy.CleanupStatus != dataplane.NodeCleanupNotObserved {
		t.Fatal("legacy zero inferred cleanup", legacy)
	}
	private := "secret-endpoint.example/private-credential"
	result.Stage = private
	result.DirectControl = private
	result.ProbeID = private
	result.CleanupStatus = dataplane.NodeCleanupStatus(private)
	item := nodeCheckItemFromResult(id, q.NetworkProfile, result, fmt.Errorf("%s: %w", private, context.Canceled), "xray")
	encoded, _ := json.Marshal(item)
	if strings.Contains(string(encoded), private) || item.Stage != "" || item.DirectControl != "" || item.ProbeID != "" || item.CleanupVerified {
		t.Fatal("private metadata escaped", string(encoded))
	}
	result = serviceDiagnosticResult(q)
	result.ErrorCode = "node-cleanup-failed"
	result.CleanupStatus = dataplane.NodeCleanupFailed
	failed := nodeCheckItemFromResult(id, q.NetworkProfile, result, errors.New(private), "xray")
	if failed.ErrorCode != "node-cleanup-failed" || failed.CleanupStatus != dataplane.NodeCleanupFailed || failed.CleanupVerified || failed.Available {
		t.Fatal("history error hid cleanup failure", failed)
	}
}

func TestServiceDTOHistoryRefusalRetainsProducerCleanup(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			a, _ := newNodeJobTest(t, 1)
			id := importXHTTPNode(t, a)
			useQuotaEngines(t, a, id, "sing-box", "xray")
			a.NodeCheckers["xray"] = jobNodeChecker(func(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				result := serviceDiagnosticResult(q)
				if failed {
					result.CleanupStatus = dataplane.NodeCleanupFailed
					result.ErrorCode = "node-cleanup-failed"
					result.Stage = "cleanup"
				}
				return result, nil
			})
			admission := 0
			a.NodeHistoryWriteGuard = func(context.Context, int) error {
				admission++
				if admission == 2 {
					return errors.New("private-history-credential")
				}
				return nil
			}
			item := a.runNodeCheckItem(context.Background(), "service", id, a.Catalog.Services[0], "", nil)
			if admission != 2 || item.Engine != "xray" || item.Verdict != "INCONCLUSIVE" || item.Available || item.ConnectivityReady || len(nodeHistory(t, a, id)) != 0 {
				t.Fatal("history admission changed", item, admission)
			}
			if failed {
				if item.CleanupVerified || item.CleanupStatus != dataplane.NodeCleanupFailed || item.ErrorCode != "node-cleanup-failed" || item.Stage != "cleanup" {
					t.Fatal("fatal cleanup lost", item)
				}
			} else if !item.CleanupVerified || item.CleanupStatus != dataplane.NodeCleanupVerified || item.Stage != "egress" {
				t.Fatal("producer observation lost", item)
			}
			encoded, _ := json.Marshal(item)
			if strings.Contains(string(encoded), "private-history-credential") {
				t.Fatal("history error leaked")
			}
		})
	}
}

func TestServiceDTOClosedServiceErrorCategory(t *testing.T) {
	id := "node-" + strings.Repeat("1", 64)
	q := dataplane.NodeCheckRequest{NodeID: id, NetworkProfile: "wan-0123456789ab"}
	for _, stage := range []string{"service", "service_ip"} {
		for _, category := range []string{"service_timeout", "service_transport", "service_status_mismatch", "private endpoint secret", ""} {
			r := serviceDiagnosticResult(q)
			r.Stage = stage
			r.ServiceErrorCategory = category
			row := nodeCheckItemFromResult(id, q.NetworkProfile, r, nil, "xray")
			want := category
			if category == "private endpoint secret" {
				want = ""
			}
			if row.ServiceErrorCategory != want || row.Available || row.ConnectivityReady {
				t.Fatal(row)
			}
			encoded, _ := json.Marshal(row)
			if strings.Contains(string(encoded), "secret") {
				t.Fatal("private category escaped")
			}
		}
	}
	for _, mismatch := range []string{"node", "network", "route", "stage"} {
		r := serviceDiagnosticResult(q)
		r.Stage = "service"
		r.ServiceErrorCategory = "service_timeout"
		switch mismatch {
		case "node":
			r.NodeID = "other"
		case "network":
			r.NetworkProfile = "other"
		case "route":
			r.RoutePathID = "other"
		case "stage":
			r.Stage = "egress"
		}
		if row := nodeCheckItemFromResult(id, q.NetworkProfile, r, nil, "xray"); row.ServiceErrorCategory != "" {
			t.Fatal("unbound service category admitted", row)
		}
	}
}
