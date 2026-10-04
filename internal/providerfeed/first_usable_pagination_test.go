package providerfeed

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestSnapshotPagedFirstUsableAppliesEntry33AfterRestart304(t *testing.T) {
	m, nodes, path := persistentManager(t)
	source := savePagedFeed(t, m)
	ctx := context.Background()
	setResponse(m, 200, pageFeed(33), http.Header{"Etag": []string{`"first-usable-pages"`}})
	first, err := m.SyncSaved(ctx, source.SourceID)
	if err != nil || len(first.NodeIDs) != 32 || first.Cursor != 32 {
		t.Fatal(first, err)
	}
	now := testTime.Add(time.Minute)
	hooks := nodestore.SearchHooks{
		Guard:         func(context.Context) error { return nil },
		PersistCursor: func(context.Context, int) error { return nil },
		Apply: func(context.Context, nodestore.ResolvedRoute) error {
			t.Fatal("unsupported first page applied")
			return nil
		},
		Now: func() time.Time { now = now.Add(time.Millisecond); return now },
		Check: func(context.Context, string) (nodestore.SearchCheck, error) {
			return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
		},
	}
	req := nodestore.SearchRequest{Engine: "xray", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", Ordered: first.NodeIDs, Limit: 4, AllowedSources: []string{source.SourceID}, Protocols: []string{"vless"}}
	search, err := nodes.SearchFirstUsable(ctx, req, hooks)
	if err != nil || search.Checks != 4 || search.Cursor != 4 || search.Applied.NodeID != "" {
		t.Fatal(search, err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = Open(nodes, path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.now = func() time.Time { return testTime.Add(2 * time.Hour) }
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != `"first-usable-pages"` {
			t.Error("restart lost snapshot validator")
		}
		return response(304, "", nil), nil
	})}
	second, err := m.SyncSaved(ctx, source.SourceID)
	if err != nil || !second.NotModified || len(second.NodeIDs) != 1 || second.Cursor != 33 || !second.OriginExpiresAt.Equal(first.OriginExpiresAt) {
		t.Fatal("restart repeated prefix or extended origin", second, err)
	}
	for _, id := range first.NodeIDs {
		if id == second.NodeIDs[0] {
			t.Fatal("page two repeated a first-page node")
		}
	}
	now = testTime.Add(2 * time.Hour)
	req.Ordered, req.Cursor = second.NodeIDs, 0
	hooks.Check = func(ctx context.Context, id string) (nodestore.SearchCheck, error) {
		at := hooks.Now()
		record := nodestore.CheckRecord{ProbeID: "fresh-entry-33", ServiceID: req.ServiceID, NetworkProfile: req.NetworkProfile, RoutePathID: "xray:" + id, TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: at, ExpiresAt: at.Add(time.Hour)}
		if _, err := nodes.RecordCheck(ctx, id, record, at); err != nil {
			return nodestore.SearchCheck{}, err
		}
		return nodestore.SearchCheck{Outcome: nodestore.SearchUsable, ProbeID: record.ProbeID, CheckedAt: at}, nil
	}
	applies := 0
	hooks.Apply = func(_ context.Context, r nodestore.ResolvedRoute) error {
		applies++
		if r.Route != "xray:"+second.NodeIDs[0] {
			t.Fatal("entry33 changed executor", r)
		}
		return nil
	}
	search, err = nodes.SearchFirstUsable(ctx, req, hooks)
	if err != nil || search.Checks != 1 || search.ApplyAttempts != 1 || applies != 1 || search.Applied.NodeID != second.NodeIDs[0] {
		t.Fatal("fresh first usable entry33 not applied immediately", search, err)
	}
}
