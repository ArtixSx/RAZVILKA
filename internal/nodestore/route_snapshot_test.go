package nodestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const routeSnapshotProfile = "wan-0123456789ab"

type routeReadCounter struct {
	restorejournal.Target
	reads atomic.Int64
	after func()
}

func (target *routeReadCounter) Read(ctx context.Context) (restorejournal.Image, error) {
	target.reads.Add(1)
	image, err := target.Target.Read(ctx)
	if target.after != nil {
		target.after()
	}
	return image, err
}

func routeSnapshotFixture(t testing.TB, count int) (*Store, []string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for start := 0; start < count; start += 128 {
		lines := []string{}
		for i := start; i < count && i < start+128; i++ {
			lines = append(lines, strings.Replace(good, "private-host.example", fmt.Sprintf("fixture-%d.example", i), 1))
		}
		if _, err := store.Import(context.Background(), manual, strings.Join(lines, "\n"), testTime, 2*time.Hour, false); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{}
	updateRouteFixture(t, store, func(doc *document) {
		for i := range doc.Nodes {
			node := &doc.Nodes[i]
			ids = append(ids, node.ID)
			node.Checks = []CheckRecord{routeSnapshotCheck(node.ID, "telegram", "pass", testTime)}
		}
	})
	return store, ids
}

func routeSnapshotCheck(id, service, probe string, checked time.Time) CheckRecord {
	return CheckRecord{ProbeID: "node-check-" + probe, ServiceID: service, NetworkProfile: routeSnapshotProfile,
		RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service",
		CheckedAt: checked, ExpiresAt: checked.Add(time.Hour), HTTPStatus: 200, Message: "Confirmed."}
}

func updateRouteFixture(t testing.TB, store *Store, update func(*document)) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	doc, before, err := store.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	update(&doc)
	if err := store.commitDocument(context.Background(), &doc, before); err != nil {
		t.Fatal(err)
	}
}

func TestRouteSnapshotExactNodeAndMixedGroupEligibility(t *testing.T) {
	store, ids := routeSnapshotFixture(t, 4)
	updateRouteFixture(t, store, func(doc *document) {
		doc.Nodes[0].Origins[0].ExpiresAt = testTime.Add(30 * time.Second)
		// The displayed history is still a PASS, but its origin is now expired.
		doc.Nodes[1].Checks = append(doc.Nodes[1].Checks, routeSnapshotCheck(ids[1], "youtube", "youtube-pass", testTime))
		failed := routeSnapshotCheck(ids[1], "youtube", "youtube-failed", testTime.Add(time.Second))
		failed.TestLevel, failed.Verdict, failed.State, failed.Stage = "protocol", "ERROR", "unavailable", "protocol"
		doc.Nodes[1].Checks = append(doc.Nodes[1].Checks, failed)
		doc.Nodes[2].Disabled = true
		doc.Nodes[3].Checks[0].NetworkProfile = "wan-ffffffffffff"
	})
	manualExpired, err := store.CreateGroup(context.Background(), "Manual expired", "manual", ids[:2], ids[0], time.Minute, testTime)
	if err != nil {
		t.Fatal(err)
	}
	manualCurrent, err := store.CreateGroup(context.Background(), "Manual current", "manual", ids[:2], ids[1], time.Minute, testTime)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := store.CreateGroup(context.Background(), "Fallback", "fallback", ids, ids[0], time.Minute, testTime)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime.Add(time.Minute)
	wantSnapshot, err := store.Snapshot(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	counter := &routeReadCounter{Target: store.target}
	store.target = counter
	view, services, err := store.RouteSnapshot(context.Background(), routeSnapshotProfile, now)
	if err != nil || counter.reads.Load() != 1 || !reflect.DeepEqual(view, wantSnapshot) {
		t.Fatalf("single-load metadata generation was not preserved: reads=%d err=%v", counter.reads.Load(), err)
	}
	expected := map[string][]string{
		ids[0]: {}, ids[1]: {"telegram"}, ids[2]: {}, ids[3]: {},
		manualExpired.ID: {}, manualCurrent.ID: {"telegram"}, fallback.ID: {"telegram"},
	}
	if !reflect.DeepEqual(services, expected) {
		t.Fatalf("private proof eligibility mismatch: got=%v want=%v", services, expected)
	}
	for _, node := range view.Nodes {
		single, err := store.RouteServices(context.Background(), node.ID, routeSnapshotProfile, now)
		if err != nil || !reflect.DeepEqual(single, services[node.ID]) {
			t.Fatal("single-node API eligibility differs")
		}
	}
	for _, group := range view.Groups {
		single, err := store.GroupServices(context.Background(), group.ID, routeSnapshotProfile, now)
		if err != nil || !reflect.DeepEqual(single, services[group.ID]) {
			t.Fatal("group API eligibility differs")
		}
	}
	if _, err := store.ResolveRoute(context.Background(), manualExpired.ID, "telegram", routeSnapshotProfile, "", time.Time{}, now); !errors.Is(err, ErrRouteProof) {
		t.Fatal("expired preferred origin still resolved")
	}
	services[manualCurrent.ID][0] = "modified"
	if services[ids[1]][0] != "telegram" || services[fallback.ID][0] != "telegram" {
		t.Fatal("group selectors alias mutable node/service slices")
	}
	public, err := json.Marshal(struct {
		Snapshot Snapshot
		Services map[string][]string
	}{view, services})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"123e4567-e89b-12d3-a456-426614174000", "fixture-0.example", "private-sni.example", "SECRET_ALIAS", "secret_ref", "identity_key"} {
		if bytes.Contains(public, []byte(secret)) {
			t.Fatal("route metadata disclosed private material")
		}
	}
}

func TestRouteSnapshotNewestAttemptRevokesPassAtEveryFailureStage(t *testing.T) {
	for _, stage := range []string{"dns", "transport", "protocol", "egress", "service"} {
		t.Run(stage, func(t *testing.T) {
			store, ids := routeSnapshotFixture(t, 1)
			failed := routeSnapshotCheck(ids[0], "telegram", "failed", testTime.Add(time.Second))
			failed.TestLevel, failed.Stage, failed.Verdict, failed.State = stage, stage, "ERROR", "unavailable"
			if _, err := store.RecordCheck(context.Background(), ids[0], failed, failed.CheckedAt); err != nil {
				t.Fatal(err)
			}
			_, services, err := store.RouteSnapshot(context.Background(), routeSnapshotProfile, testTime.Add(time.Minute))
			if err != nil || len(services[ids[0]]) != 0 {
				t.Fatalf("old PASS survived a newer exact failure: %v", err)
			}
		})
	}
}

func TestRouteSnapshotRejectsInvalidAndStaleAuthority(t *testing.T) {
	store, ids := routeSnapshotFixture(t, 1)
	counter := &routeReadCounter{Target: store.target}
	store.target = counter
	for _, profile := range []string{"", "bad profile", "network-unknown", "wan-invalid"} {
		if view, services, err := store.RouteSnapshot(context.Background(), profile, testTime); err == nil || view.Generation != 0 || services != nil {
			t.Fatal("invalid network profile returned partial authority")
		}
	}
	if _, _, err := store.RouteSnapshot(context.Background(), routeSnapshotProfile, time.Time{}); !errors.Is(err, ErrStore) || counter.reads.Load() != 0 {
		t.Fatal("invalid query read private storage")
	}
	for _, scenario := range []struct {
		profile string
		now     time.Time
	}{
		{"wan-ffffffffffff", testTime.Add(time.Minute)},
		{routeSnapshotProfile, testTime.Add(-time.Second)},
		{routeSnapshotProfile, testTime.Add(time.Hour)},
	} {
		_, services, err := store.RouteSnapshot(context.Background(), scenario.profile, scenario.now)
		if err != nil || len(services[ids[0]]) != 0 {
			t.Fatal("wrong epoch/future/expired proof granted authority")
		}
	}
	updateRouteFixture(t, store, func(doc *document) { doc.Nodes[0].Checks[0].DirectLeak = true })
	_, services, err := store.RouteSnapshot(context.Background(), routeSnapshotProfile, testTime)
	if err != nil || len(services[ids[0]]) != 0 {
		t.Fatal("direct-leak PASS granted authority")
	}
	// Even an inconsistent manual group passed to the private helper cannot
	// obtain permission from a preferred ID outside its explicit membership.
	unlisted := routeServicesForGroup(NodeGroup{Mode: "manual", NodeIDs: []string{"member"}, PreferredNodeID: "foreign"},
		map[string][]string{"foreign": {"telegram"}})
	if len(unlisted) != 0 {
		t.Fatal("manual group widened to a nonmember")
	}
}

func TestRouteSnapshotCancellationDiscardsPartialResultsAndDoesNotQueue(t *testing.T) {
	store, _ := routeSnapshotFixture(t, 1)
	counter := &routeReadCounter{Target: store.target}
	store.target = counter
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if view, services, err := store.RouteSnapshot(ctx, routeSnapshotProfile, testTime); !errors.Is(err, context.Canceled) || view.Generation != 0 || services != nil || counter.reads.Load() != 0 {
		t.Fatal("canceled request loaded or returned private route state")
	}
	ctx, cancel = context.WithCancel(context.Background())
	counter.after = cancel
	if view, services, err := store.RouteSnapshot(ctx, routeSnapshotProfile, testTime); !errors.Is(err, context.Canceled) || view.Generation != 0 || services != nil || counter.reads.Load() != 1 {
		t.Fatal("cancellation during read returned partial authority")
	}
	counter.after = nil
	store.mu.Lock()
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, _, err := store.RouteSnapshot(ctx, routeSnapshotProfile, testTime)
		finished <- err
	}()
	select {
	case err := <-finished:
		store.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) || counter.reads.Load() != 1 {
			t.Fatal("queued cancellation acquired the private document")
		}
	case <-time.After(time.Second):
		store.mu.Unlock()
		<-finished
		t.Fatal("canceled selector remained queued behind a held mutex")
	}
}

func TestRouteSnapshotLoadsLargeEnvelopeOnce(t *testing.T) {
	store, ids := routeSnapshotFixture(t, 344)
	counter := &routeReadCounter{Target: store.target}
	store.target = counter
	view, services, err := store.RouteSnapshot(context.Background(), routeSnapshotProfile, testTime)
	if err != nil || len(view.Nodes) != len(ids) || len(services) != len(ids) || counter.reads.Load() != 1 {
		t.Fatalf("large envelope read count=%d err=%v", counter.reads.Load(), err)
	}
	for _, id := range ids {
		if !reflect.DeepEqual(services[id], []string{"telegram"}) {
			t.Fatal("large snapshot lost exact proof")
		}
	}
}

func BenchmarkRouteSelectorSnapshot344(b *testing.B) {
	store, ids := routeSnapshotFixture(b, 344)
	counter := &routeReadCounter{Target: store.target}
	store.target = counter
	for _, batched := range []bool{false, true} {
		name := "RepeatedNodeReads"
		if batched {
			name = "OneRouteSnapshot"
		}
		b.Run(name, func(b *testing.B) {
			counter.reads.Store(0)
			b.ReportAllocs()
			for b.Loop() {
				if batched {
					if _, _, err := store.RouteSnapshot(context.Background(), routeSnapshotProfile, testTime); err != nil {
						b.Fatal(err)
					}
				} else {
					for _, id := range ids {
						if _, err := store.RouteServices(context.Background(), id, routeSnapshotProfile, testTime); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
			b.ReportMetric(float64(counter.reads.Load())/float64(b.N), "private_reads/op")
		})
	}
}
