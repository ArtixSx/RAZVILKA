package app

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodecleanup"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// serviceOutcomeResult models a checker result after proven exact egress: a
// measured direct control, a published egress IP and then the service stage.
func serviceOutcomeResult(request dataplane.NodeCheckRequest, kind string, serial int) dataplane.NodeCheckResult {
	r := autofallbackResult(request, false)
	r.ProbeID = fmt.Sprintf("probe-service-outcome-%d", serial)
	r.EgressIP = "203.0.113.20"
	outcome := evidence.OutcomeTransportReachable
	switch kind {
	case "http-404":
		r.Verdict, r.HTTPStatus, r.ErrorCode = evidence.VerdictPartial, 404, "http-404"
	case "http-403":
		r.Verdict, r.HTTPStatus, r.ErrorCode, outcome = evidence.VerdictBlocked, 403, "http-403", evidence.OutcomeServiceBlocked
	case "body-mismatch":
		r.Verdict, r.HTTPStatus, r.ErrorCode, outcome = evidence.VerdictError, 200, "body-predicate-mismatch", evidence.OutcomeContentMismatch
	case "service-timeout":
		r.Verdict, r.HTTPStatus, r.ErrorCode, outcome = evidence.VerdictError, 0, "request-failed", evidence.OutcomeUnknown
	case "server-error":
		r.Verdict, r.HTTPStatus, r.ErrorCode = evidence.VerdictError, 503, "http-503"
	case "retry-later":
		r.Verdict, r.HTTPStatus, r.ErrorCode = evidence.VerdictPartial, 408, "http-408"
	case "unexpected-status":
		r.Verdict, r.HTTPStatus, r.ErrorCode = evidence.VerdictInconclusive, 200, "unexpected-http-status"
	case "service-ip":
		r.Stage, r.Verdict, r.HTTPStatus, r.ErrorCode = "service_ip", evidence.VerdictError, 204, "node-service-ip-path-failed"
	case "no-direct-control":
		r.Verdict, r.HTTPStatus, r.ErrorCode, r.DirectControl = evidence.VerdictPartial, 404, "http-404", "unavailable"
	case "config-rejected":
		r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.ErrorCode, r.DirectControl = "protocol", "configuration", evidence.VerdictError, "", "node-runtime-config-rejected", ""
	case "egress-control-unavailable":
		r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.ErrorCode, r.DirectControl = "egress", "egress", evidence.VerdictInconclusive, "", "node-egress-control-unavailable", "unavailable"
	case "direct-leak":
		r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.ErrorCode, r.DirectLeak = "egress", "egress", evidence.VerdictMisrouted, "", "node-direct-leak", true
	case "egress-failed":
		r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.ErrorCode = "protocol", "egress", evidence.VerdictError, "", "node-egress-failed"
	default:
		panic("unknown service outcome " + kind)
	}
	r.Evidence.ProbeID, r.Evidence.Verdict, r.Evidence.Outcome, r.Evidence.HTTPStatus, r.Evidence.ErrorCode = r.ProbeID, r.Verdict, outcome, r.HTTPStatus, r.ErrorCode
	r.Evidence.EgressIP = r.EgressIP
	r.Message = "Узел передаёт трафик, но выбранный сервис через него не подтверждён."
	return r
}

// serviceRefusalFixture adds candidates to the integration fixture so that a
// traversal is long enough for the refusal guard.
func serviceRefusalFixture(t *testing.T, extra int) (*App, []string, *nodeApplyAdapter) {
	t.Helper()
	a, ids, adapter := autonomousIntegrationFixture(t)
	rows := []string{}
	for i := range extra {
		rows = append(rows, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-4266141740%02d@refusal-%d.example:443?security=tls", 20+i, i))
	}
	if extra > 0 {
		snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, strings.Join(rows, "\n"), time.Now(), time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		ids = ids[:0]
		for _, n := range snapshot.Nodes {
			ids = append(ids, n.ID)
		}
		slices.Sort(ids)
		d10Options(a, ids)
	}
	return a, ids, adapter
}

func TestAutonomyServiceRefusalAfterProvenEgressAdvancesToNextNode(t *testing.T) {
	for _, kind := range []string{"http-404", "body-mismatch", "http-403"} {
		t.Run(kind, func(t *testing.T) {
			a, _, adapter := serviceRefusalFixture(t, 0)
			checked := []string{}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, request.NodeID)
				if len(checked) == 1 {
					return serviceOutcomeResult(request, kind, len(checked)), nil
				}
				return d10Result(request, "sing-box", true), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if r.State != "applied" || r.Search == nil || r.Search.Cursor != 2 || !reflect.DeepEqual(checked, r.Search.Ordered[:2]) || len(r.CandidateFailures) != 0 ||
				selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+checked[1] || !slices.Contains(adapter.calls, "commit") {
				t.Fatal("definite service refusal did not advance to the next node in one round", r.State, r.Search, checked, adapter.calls)
			}
		})
	}
}

func TestAutonomyServiceOutcomesWithoutDefiniteRefusalKeepCursor(t *testing.T) {
	for _, kind := range []string{"service-timeout", "server-error", "retry-later", "unexpected-status", "service-ip", "no-direct-control", "config-rejected", "egress-control-unavailable", "direct-leak"} {
		t.Run(kind, func(t *testing.T) {
			a, _, adapter := serviceRefusalFixture(t, 0)
			checked := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked++
				if checked > 1 {
					return d10Result(request, "sing-box", true), nil
				}
				return serviceOutcomeResult(request, kind, checked), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if checked != 1 || r.State != "unconfirmed" || r.Search == nil || r.Search.Cursor != 0 || r.Search.Exhausted || len(r.CandidateFailures) != 0 || len(adapter.calls) != 0 {
				t.Fatal("non-definite outcome consumed the node or checked a peer", r.State, r.Search, checked, adapter.calls)
			}
		})
	}
}

// Three consumed service refusals in a row look like a service or path
// problem. The search pauses with a closed reason and RetryAt instead of
// consuming the rest of the list, and never penalizes the refused nodes.
func TestAutonomyThreeServiceRefusalsPauseSearch(t *testing.T) {
	a, ids, adapter := serviceRefusalFixture(t, 3)
	if len(ids) != 5 {
		t.Fatal("fixture candidates", len(ids))
	}
	kinds := []string{"http-404", "http-403", "body-mismatch", "http-404"}
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		if len(checked) <= len(kinds) {
			return serviceOutcomeResult(request, kinds[len(checked)-1], len(checked)), nil
		}
		return d10Result(request, "sing-box", true), nil
	})
	// Round 1 consumes two refusals (two checks per round); the run of
	// refusals continues across rounds of the same traversal.
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "searching" || r.Search.Cursor != 2 || len(checked) != 2 {
		t.Fatal("first round", r.State, r.Search, checked)
	}
	autonomyTestDue(a, false)
	before := time.Now()
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "service-unconfirmed" || r.Message != autonomyServiceUnconfirmedMessage || r.Search.Cursor != 3 || r.Search.Exhausted || len(checked) != 3 ||
		r.Search.RetryAt.Before(before.Add(time.Duration(a.autonomyPolicy().ReserveSeconds)*time.Second)) || !reflect.DeepEqual(checked, r.Search.Ordered[:3]) {
		t.Fatal("third consecutive refusal did not pause the search with RetryAt", r.State, r.Search, checked)
	}
	if len(r.CandidateFailures) != 0 || r.Failures != 0 || len(adapter.calls) != 0 {
		t.Fatal("refusals produced candidate failures, a failure quorum or Apply", r.CandidateFailures, r.Failures, adapter.calls)
	}
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := a.freshNetworkProfile(context.Background())
	if err != nil || len(snapshot.Nodes) != len(ids) {
		t.Fatal("refused nodes were removed", err)
	}
	for _, n := range snapshot.Nodes {
		if n.Disabled || slices.Contains(checked, n.ID) && nodecleanup.Eligible(n.ID, "my-independent-site", profile, cleanupChecks(n), time.Now(), true) {
			t.Fatal("refused node disabled or made cleanup-eligible", n.ID)
		}
	}
	// The pause holds: a due round checks nothing and keeps the cursor.
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "service-unconfirmed" || r.Search.Cursor != 3 || len(checked) != 3 {
		t.Fatal("paused search checked another node", r.State, r.Search, checked)
	}
	// After RetryAt the search resumes at the cursor with a new run.
	a.autonomy.mu.Lock()
	g := a.autonomy.serviceRefusals["my-independent-site"]
	g.until = time.Now().Add(-time.Second)
	a.autonomy.serviceRefusals["my-independent-site"] = g
	a.autonomy.mu.Unlock()
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	r = autonomyTestState(a)
	if r.State != "applied" || len(checked) != 5 || !reflect.DeepEqual(checked, r.Search.Ordered) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+checked[4] {
		t.Fatal("search did not resume after the pause", r.State, r.Search, checked)
	}
}

// Another observed outcome ends the run: refusals separated by a node failure
// never reach the guard, and every consumed node is checked once.
func TestAutonomyServiceRefusalRunEndsOnOtherOutcome(t *testing.T) {
	a, ids, _ := serviceRefusalFixture(t, 3)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.CandidatesPerRound = 4
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	kinds := []string{"http-404", "http-404", "egress-failed", "http-404"}
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		if len(checked) <= len(kinds) {
			return serviceOutcomeResult(request, kinds[len(checked)-1], len(checked)), nil
		}
		return d10Result(request, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "searching" || r.Search.Cursor != 4 || len(checked) != 4 || len(r.CandidateFailures) != 0 {
		t.Fatal("a broken run of refusals paused or stalled the search", r.State, r.Search, checked)
	}
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "applied" || !reflect.DeepEqual(checked, r.Search.Ordered) || len(ids) != 5 {
		t.Fatal("search did not reach the usable node", r.State, r.Search, checked)
	}
}
