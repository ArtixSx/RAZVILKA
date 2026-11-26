package app

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func connectivityCooldownFixture(node, other, network string, now time.Time) ([]nodeCheckItem, nodeCheckItem) {
	failed := func(probe string, ago time.Duration) nodeCheckItem {
		at := now.Add(-ago)
		return nodeCheckItem{NodeID: node, Engine: "sing-box", NetworkProfile: network, ProbeID: probe, CheckedAt: at, ExpiresAt: at.Add(dataplane.NodeConnectivityTTL),
			TestLevel: "connectivity", Stage: "transport", Verdict: "ERROR", ErrorCode: "node-transport-failed", DirectControl: "not_run", CleanupVerified: true}
	}
	positive := nodeCheckItem{NodeID: other, Engine: "sing-box", NetworkProfile: network, ProbeID: "other-positive", CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		TestLevel: "connectivity", Stage: "connectivity", Verdict: "PASS", DirectControl: "measured", CleanupVerified: true, ConnectivityReady: true}
	return []nodeCheckItem{failed("first-failure", 2*time.Minute), failed("second-failure", time.Minute)}, positive
}

func TestConnectivityCooldownRequiresTwoFailuresAndNewerOtherPositive(t *testing.T) {
	now := time.Now().UTC()
	for _, scenario := range []string{"valid", "no-positive", "only-one", "same-node", "old-positive", "positive-between", "other-engine", "other-network", "positive-expired", "positive-future", "positive-unclean", "positive-unmeasured", "positive-no-proof", "positive-429", "positive-foreign-stage", "duplicate-probe", "wide-failure-window", "failure-expired", "failure-future", "failure-unclean", "service-failure", "egress-provider", "dns", "stop", "resource", "wan-unknown", "first-own-ttl-expired"} {
		t.Run(scenario, func(t *testing.T) {
			pair, positive := connectivityCooldownFixture("failed", "other", "wan-one", now)
			switch scenario {
			case "only-one":
				pair = pair[:1]
			case "same-node":
				positive.NodeID = "failed"
			case "old-positive":
				positive.CheckedAt = pair[0].CheckedAt.Add(-time.Second)
			case "positive-between":
				positive.CheckedAt = pair[0].CheckedAt.Add(time.Second)
			case "other-engine":
				positive.Engine = "xray"
			case "other-network":
				positive.NetworkProfile = "wan-two"
			case "positive-expired":
				positive.ExpiresAt = now
			case "positive-future":
				positive.CheckedAt = now.Add(time.Second)
			case "positive-unclean":
				positive.CleanupVerified = false
			case "positive-unmeasured":
				positive.DirectControl = "unavailable"
			case "positive-no-proof":
				positive.ConnectivityReady = false
			case "positive-429":
				positive.ErrorCode, positive.Verdict = "http-429", "PARTIAL"
			case "positive-foreign-stage":
				positive.Stage = "service"
			case "duplicate-probe":
				pair[1].ProbeID = pair[0].ProbeID
			case "wide-failure-window":
				pair[0].CheckedAt = pair[1].CheckedAt.Add(-6 * time.Minute)
				pair[0].ExpiresAt = pair[0].CheckedAt.Add(dataplane.NodeConnectivityTTL)
			case "failure-expired":
				for i := range pair {
					pair[i].CheckedAt = pair[i].CheckedAt.Add(-5 * time.Minute)
					pair[i].ExpiresAt = pair[i].CheckedAt.Add(dataplane.NodeConnectivityTTL)
				}
			case "failure-future":
				pair[1].CheckedAt = now.Add(time.Second)
			case "failure-unclean":
				pair[1].CleanupVerified = false
			case "service-failure":
				pair[1].Stage, pair[1].ErrorCode = "service", "http-status-blocked"
			case "egress-provider":
				pair[1].Stage, pair[1].ErrorCode = "egress", "node-egress-failed"
			case "dns":
				pair[1].Stage, pair[1].ErrorCode = "dns", "node-dns-failed"
			case "stop":
				pair[1].ErrorCode = "node-check-canceled"
			case "resource":
				pair[1].ErrorCode = "node-resource-refused"
			case "wan-unknown":
				pair[1].ErrorCode = "node-network-changed"
			case "first-own-ttl-expired":
				pair[0].CheckedAt = pair[1].CheckedAt.Add(-5 * time.Minute)
				pair[0].ExpiresAt = pair[0].CheckedAt.Add(dataplane.NodeConnectivityTTL)
			}
			a := &App{}
			a.nodeChecks.connectivityTransportFailures = map[string][]nodeCheckItem{"failed\x00sing-box\x00wan-one": pair}
			if scenario != "no-positive" {
				a.nodeChecks.connectivity = map[string]nodeCheckItem{positive.NodeID: positive}
			}
			want := scenario == "valid" || scenario == "first-own-ttl-expired"
			if got := a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", now); got != want {
				t.Fatal("wrong scheduling attribution", got)
			}
			if a.nodeConnectivityTransportCoolingDown("failed", "xray", "wan-one", now) || a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-two", now) {
				t.Fatal("negative escaped its executor/WAN")
			}
			before := append([]nodeCheckItem(nil), pair...)
			_ = a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", now.Add(2*time.Minute))
			if !reflect.DeepEqual(before, a.nodeChecks.connectivityTransportFailures["failed\x00sing-box\x00wan-one"]) {
				t.Fatal("read changed the cooldown deadline")
			}
			if a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", pair[len(pair)-1].CheckedAt.Add(dataplane.NodeConnectivityTTL)) {
				t.Fatal("cooldown outlived last failure + five minutes")
			}
		})
	}
}

func TestConnectivityCooldownLaterPositiveCannotRenewFixedDeadline(t *testing.T) {
	now := time.Now().UTC()
	pair, positive := connectivityCooldownFixture("failed", "other", "wan-one", now)
	positive.CheckedAt = now.Add(2 * time.Minute)
	positive.ExpiresAt = positive.CheckedAt.Add(dataplane.NodeConnectivityTTL)
	a := &App{}
	a.nodeChecks.connectivityTransportFailures = map[string][]nodeCheckItem{"failed\x00sing-box\x00wan-one": pair}
	a.nodeChecks.connectivity = map[string]nodeCheckItem{"other": positive}
	if !a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", now.Add(3*time.Minute)) {
		t.Fatal("newer positive did not qualify existing pair")
	}
	if a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", pair[1].CheckedAt.Add(dataplane.NodeConnectivityTTL)) {
		t.Fatal("later positive extended the negative deadline")
	}
}

func TestConnectivityCooldownPositiveClearsPairAndReadsDoNotAddFailures(t *testing.T) {
	now := time.Now().UTC()
	pair, positive := connectivityCooldownFixture("failed", "other", "wan-one", now)
	a := &App{}
	a.nodeChecks.mu.Lock()
	a.rememberNodeConnectivityLocked(pair[0])
	a.rememberNodeConnectivityLocked(pair[1])
	a.rememberNodeConnectivityLocked(positive)
	a.nodeChecks.mu.Unlock()
	if !a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", now) {
		t.Fatal("real cache writes did not qualify pair")
	}
	positive.NodeID, positive.ProbeID, positive.CheckedAt = "failed", "recovered-positive", now
	positive.ExpiresAt = now.Add(dataplane.NodeConnectivityTTL)
	a.nodeChecks.mu.Lock()
	a.rememberNodeConnectivityLocked(positive)
	a.nodeChecks.mu.Unlock()
	for i := 0; i < 3; i++ {
		if a.nodeConnectivityTransportCoolingDown("failed", "sing-box", "wan-one", now) {
			t.Fatal("positive did not clear previous failures")
		}
	}
	if len(a.nodeChecks.connectivityTransportFailures["failed\x00sing-box\x00wan-one"]) != 0 {
		t.Fatal("read recreated a cleared pair")
	}
}

func TestConnectivityCooldownDurableProducerWriterConsumerLifecycle(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	ids := append([]string(nil), request.NodeIDs...)
	request.Mode, request.ServiceID = "connectivity", ""
	request.NodeIDs = ids[:1]
	before, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	calls, recovered := 0, false
	a.NodeChecker = connectivityJobChecker{run: func(_ context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
		calls++
		result := readyConnectivity(r)
		result.ProbeID = fmt.Sprintf("producer-check-%d", calls)
		if r.NodeID == ids[0] && !recovered {
			result.Ready, result.Stage, result.ErrorCode, result.DirectControl, result.Verdict, result.HTTPStatus = false, "transport", "node-transport-failed", "not_run", evidence.VerdictError, 0
		}
		return result, nil
	}}
	run := func(key string) {
		t.Helper()
		request.IdempotencyKey = key
		id := enqueueNodeFixture(t, a, request)
		// The existing scheduler yields after three consecutive durable jobs.
		// Model its next tick without bypassing that fairness boundary.
		for tick := 0; tick < 2; tick++ {
			a.runDurableServiceJob(context.Background(), time.Now())
			if durableJobAt(t, a, id).State == "completed" {
				break
			}
		}
		if job := durableJobAt(t, a, id); job.State != "completed" {
			t.Fatal("producer job did not close", key, job.State, job.Cursor, len(job.Request.NodeIDs), job.Reason)
		}
	}
	run("cooldown-first-failure")
	network := a.nodeChecks.connectivity[ids[0]].NetworkProfile
	if a.nodeConnectivityTransportCoolingDown(ids[0], "sing-box", network, time.Now()) {
		t.Fatal("one timeout penalized a node")
	}
	run("cooldown-second-failure")
	if a.nodeConnectivityTransportCoolingDown(ids[0], "sing-box", network, time.Now()) {
		t.Fatal("two failures without later other positive penalized a node")
	}
	request.NodeIDs = ids[1:2]
	run("cooldown-other-positive")
	if !a.nodeConnectivityTransportCoolingDown(ids[0], "sing-box", network, time.Now()) {
		t.Fatal("newer other-node success did not qualify transport pair")
	}
	// Explicit user checks remain admitted during this automatic-only pause.
	recovered, request.NodeIDs = true, ids[:1]
	run("cooldown-explicit-positive")
	if a.nodeConnectivityTransportCoolingDown(ids[0], "sing-box", network, time.Now()) {
		t.Fatal("fresh positive failed to reset the pair")
	}
	after, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("connectivity scheduling wrote service history or node metadata", err)
	}
}

func TestConnectivityCooldownAUTOUsesActualCompatibleExecutor(t *testing.T) {
	a, _, _, id := autonomyXHTTPFixture(t)
	now := time.Now().UTC()
	pair, positive := connectivityCooldownFixture(id, "other", "wan-one", now)
	a.nodeChecks.connectivityTransportFailures = map[string][]nodeCheckItem{id + "\x00sing-box\x00wan-one": pair}
	a.nodeChecks.connectivity = map[string]nodeCheckItem{"other-sing": positive}
	p, s := autonomy.Default(), autonomy.Service{ID: "discord", ExpectedRoute: "auto"}
	if a.autonomyConnectivityCoolingDown(context.Background(), p, s, "sing-box", id, "wan-one", now) {
		t.Fatal("Sing-box failures suppressed an Xray-compatible AUTO candidate")
	}
	for i := range pair {
		pair[i].Engine = "xray"
	}
	positive.Engine = "xray"
	a.nodeChecks.connectivityTransportFailures[id+"\x00xray\x00wan-one"] = pair
	a.nodeChecks.connectivity["other-xray"] = positive
	if !a.autonomyConnectivityCoolingDown(context.Background(), p, s, "sing-box", id, "wan-one", now) {
		t.Fatal("actual Xray candidate ignored its own verified transport cooldown")
	}
	// Executor consent/availability is still independently checked by AUTO;
	// the hint cannot invent an executor or turn its failure into permission.
	p.PreferredRoutes = []string{"sing-box"}
	if a.autonomyConnectivityCoolingDown(context.Background(), p, s, "sing-box", id, "wan-one", now) {
		t.Fatal("unsupported executor was classified by a scheduling hint")
	}
}

func TestConnectivityCooldownNeverStopsHealthyCurrentPrimary(t *testing.T) {
	a, ids, adapter := autonomyThreeReserveFixture(t)
	ctx := context.Background()
	network, err := a.freshNetworkProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pair, positive := connectivityCooldownFixture(ids[0], ids[1], network, time.Now().UTC())
	a.nodeChecks.connectivityTransportFailures = map[string][]nodeCheckItem{ids[0] + "\x00sing-box\x00" + network: pair}
	a.nodeChecks.connectivity = map[string]nodeCheckItem{ids[1]: positive}
	if !a.nodeConnectivityTransportCoolingDown(ids[0], "sing-box", network, time.Now()) {
		t.Fatal("fixture did not qualify the hint")
	}
	before := a.Store.Get()
	switches := append([]time.Time(nil), autonomyTestState(a).Switches...)
	primaryChecks := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if r.NodeID == ids[0] {
			primaryChecks++
		}
		return d10Result(r, "sing-box", true), nil
	})
	autonomyTestDue(a, false)
	a.autonomyRound(ctx, time.Now())
	after := autonomyTestState(a)
	if primaryChecks != 1 || after.State != "healthy" || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[0] || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(switches, after.Switches) || !reflect.DeepEqual(adapter.calls, []string{"health"}) {
		t.Fatal("scheduling hint stopped/replaced a healthy primary", primaryChecks, after.State, adapter.calls)
	}
}

func TestConnectivityCooldownSelectionStillRequiresFreshServiceProofAndKeepsDisabled(t *testing.T) {
	for _, disableGood := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh-service-proof", true: "disabled-stays-disabled"}[disableGood], func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			ctx := context.Background()
			network, err := a.freshNetworkProfile(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pair, positive := connectivityCooldownFixture(ids[0], ids[1], network, time.Now().UTC())
			a.nodeChecks.connectivityTransportFailures = map[string][]nodeCheckItem{ids[0] + "\x00sing-box\x00" + network: pair}
			a.nodeChecks.connectivity = map[string]nodeCheckItem{ids[1]: positive}
			if disableGood {
				if _, err := a.Nodes.SetDisabled(ctx, ids[1], true, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			before, err := a.Nodes.Snapshot(ctx, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, r.NodeID)
				if r.NodeID != ids[1] || disableGood {
					t.Fatal("cooling-down/disabled node reached service check")
				}
				return d10Result(r, "sing-box", true), nil
			})
			a.autonomyRound(ctx, time.Now())
			after, err := a.Nodes.Snapshot(ctx, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Nodes) != len(before.Nodes) {
				t.Fatal("soft backoff deleted a node")
			}
			if disableGood {
				if len(checked) != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, after) {
					t.Fatal("backoff revived a disabled node or mutated passive state")
				}
			} else if !reflect.DeepEqual(checked, []string{ids[1]}) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
				t.Fatal("generic connectivity replaced fresh service check", checked)
			}
			// Reopening loses this RAM-only hint, never leaving a permanent ban.
			if (&App{}).nodeConnectivityTransportCoolingDown(ids[0], "sing-box", network, time.Now()) {
				t.Fatal("negative became durable")
			}
		})
	}
}
