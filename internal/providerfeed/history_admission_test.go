package providerfeed

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func historyXHTTPFeedURI() string {
	return strings.Replace(goodURI, "type=tcp", "type=xhttp&mode=packet-up&host=front.example&path=%2Ftunnel", 1)
}

func historyFeedBodies(t *testing.T, path string) map[string][]byte {
	t.Helper()
	bodies := map[string][]byte{}
	entries, err := os.ReadDir(filepath.Join(path, snapshotDirectory))
	if errors.Is(err, os.ErrNotExist) {
		return bodies
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(path, snapshotDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		bodies[entry.Name()] = body
	}
	return bodies
}

func TestFeedHistoryAdmissionRefusalPreservesReservationCandidatesAndHealth(t *testing.T) {
	for _, mode := range []string{"nil", "error", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			m, nodes, path := persistentManager(t)
			feed := saveFeed(t, m, true)
			setResponse(m, http.StatusOK, goodURI, nil)
			first, err := m.SyncSaved(context.Background(), feed.SourceID)
			if err != nil {
				t.Fatal(err)
			}
			id := first.NodeIDs[0]
			if _, err := nodes.RecordCheck(context.Background(), id, nodestore.CheckRecord{ProbeID: "history-baseline", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour)}, testTime); err != nil {
				t.Fatal(err)
			}
			beforeNodes, err := nodes.ExportPrivate(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			beforeBodies := historyFeedBodies(t, path)
			beforeState := m.List()[0]
			m.now = func() time.Time { return testTime.Add(time.Minute) }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reservation []byte
			closed := make(chan struct{})
			m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				var err error
				// This legacy retry reservation is intentionally durable before
				// fetch. New incoming material has not been persisted yet.
				reservation, err = os.ReadFile(filepath.Join(path, FileName))
				if err != nil {
					t.Fatal(err)
				}
				resp := response(http.StatusOK, historyXHTTPFeedURI(), nil)
				resp.Body = feedCloseSignal{resp.Body, closed}
				return resp, nil
			})}
			calls, enters := 0, 0
			var held atomic.Bool
			if mode != "nil" {
				m.HistoryWriteAdmission = func(c context.Context, required int) error {
					calls++
					if required != 3 || !held.Load() || enters != 2 || !m.mu.TryLock() {
						t.Fatal("guard lost exact incoming capability/admission or retained feed lock")
					}
					m.mu.Unlock()
					select {
					case <-closed:
					default:
						t.Fatal("guard ran before full parse/transport cleanup")
					}
					if _, err := nodes.RequiredHistoryReadVersion(c); err != nil {
						t.Fatal("guard retained Store lock", err)
					}
					switch mode {
					case "panic":
						panic("private-panic-token")
					case "cancel":
						cancel()
						return nil
					default:
						return errors.New("private-callback-token")
					}
				}
			}
			result, err := m.SyncSavedWithAdmission(ctx, feed.SourceID, func(context.Context) (func(), error) {
				enters++
				if !held.CompareAndSwap(false, true) {
					t.Fatal("operation lease nested")
				}
				return func() { held.Store(false) }, nil
			})
			want := ErrHistoryAdmission
			if mode == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || result.Imported != 0 || len(result.NodeIDs) != 0 || held.Load() || mode != "nil" && calls != 1 {
				t.Fatal("guard refusal allowed candidate persistence or lost cancellation", err)
			}
			if strings.Contains(err.Error(), "private-") || ErrorCode(ErrHistoryAdmission) != "FEED_HISTORY_ADMISSION" {
				t.Fatal("private callback/panic text escaped sanitized admission code")
			}
			afterNodes, err := nodes.ExportPrivate(context.Background())
			if err != nil || !bytes.Equal(beforeNodes.Content, afterNodes.Content) {
				t.Fatal("guard refusal changed node bytes/generation/origin/history", err)
			}
			after, err := os.ReadFile(filepath.Join(path, FileName))
			if err != nil || !bytes.Equal(reservation, after) || !reflect.DeepEqual(beforeBodies, historyFeedBodies(t, path)) {
				t.Fatal("guard refusal promoted feed state/cursor or wrote a candidate body", err)
			}
			state := m.List()[0]
			if state.OriginExpiresAt != beforeState.OriginExpiresAt || state.LastSuccessAt != beforeState.LastSuccessAt || state.Cursor != beforeState.Cursor {
				t.Fatal("guard refusal refreshed cached authority")
			}
		})
	}
}

func TestFeedHistoryAdmissionFollowsPartialAcceptanceAndGuardsLegacyImports(t *testing.T) {
	for _, mode := range []string{"partial-unconfirmed", "partial-accepted", "legacy-bound", "legacy-unbound"} {
		t.Run(mode, func(t *testing.T) {
			m, nodes, _ := testManager(t)
			body := strings.Replace(goodURI, "node.example.org", "new-node.example.org", 1)
			partial := strings.HasPrefix(mode, "partial")
			if partial {
				body = historyXHTTPFeedURI() + "\n" + strings.Replace(historyXHTTPFeedURI(), "mode=packet-up", "mode=unsupported", 1)
			}
			setResponse(m, http.StatusOK, body, nil)
			calls := 0
			if mode != "legacy-unbound" {
				m.HistoryWriteAdmission = func(ctx context.Context, required int) error {
					calls++
					want := 1
					if partial {
						want = 3
					}
					if required != want {
						t.Fatal("incoming minimum was over/under-fenced", required)
					}
					return ErrHistoryAdmission
				}
			}
			_, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/history", AcceptPartial: mode == "partial-accepted"})
			wantErr, wantCalls, wantNodes := ErrHistoryAdmission, 1, 0
			if mode == "partial-unconfirmed" {
				wantErr, wantCalls = ErrPartial, 0
			}
			if mode == "legacy-unbound" {
				wantErr, wantCalls, wantNodes = nil, 0, 1
			}
			snap, snapshotErr := nodes.Snapshot(context.Background(), testTime)
			if !errors.Is(err, wantErr) || calls != wantCalls || snapshotErr != nil || len(snap.Nodes) != wantNodes {
				t.Fatal("partial confirmation or bound legacy guard was bypassed", err, calls, snapshotErr)
			}
		})
	}
}

func TestFeedHistoryAdmissionRevalidatesSourceAfterUnlockedCallback(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	feed := saveFeed(t, m, true)
	setResponse(m, http.StatusOK, historyXHTTPFeedURI(), nil)
	m.HistoryWriteAdmission = func(ctx context.Context, required int) error {
		if required != 3 {
			t.Fatal("incorrect incoming capability")
		}
		_, err := m.Save(ctx, feed.SourceID, SaveRequest{Request: Request{URL: "https://feed.example.org/private-path-token?secret=query-token", Limit: 128}, Enabled: false, Revision: feed.Revision})
		return err
	}
	if _, err := m.SyncSaved(context.Background(), feed.SourceID); !errors.Is(err, ErrConflict) {
		t.Fatal("stale response ignored a source edit during unlocked admission", err)
	}
	if snap, err := nodes.Snapshot(context.Background(), testTime); err != nil || len(snap.Nodes) != 0 {
		t.Fatal("stale admitted candidate reached NodeStore", err)
	}
}

func TestFeedHistoryAdmissionGuardsCached304PageWithoutAdvancingCursor(t *testing.T) {
	m, nodes, path := persistentManager(t)
	feed := savePagedFeed(t, m)
	setResponse(m, http.StatusOK, pageFeed(32)+"\n"+historyXHTTPFeedURI(), http.Header{"Etag": []string{`"history-v1"`}})
	var requirements []int
	m.HistoryWriteAdmission = func(ctx context.Context, required int) error {
		requirements = append(requirements, required)
		return ctx.Err()
	}
	first, err := m.SyncSaved(context.Background(), feed.SourceID)
	if err != nil || first.Cursor != 32 || first.SnapshotEntries != 33 || !reflect.DeepEqual(requirements, []int{1}) {
		t.Fatal("first bounded RAW page did not preserve the existing cursor contract", first, err, requirements)
	}
	beforeNodes, err := nodes.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeBodies := historyFeedBodies(t, path)
	beforeState := m.List()[0]
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = Open(nodes, path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.now = func() time.Time { return testTime.Add(2 * time.Hour) }
	var reservation []byte
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != `"history-v1"` {
			t.Fatal("cached page lost its exact response validator")
		}
		var err error
		reservation, err = os.ReadFile(filepath.Join(path, FileName))
		if err != nil {
			t.Fatal(err)
		}
		return response(http.StatusNotModified, "", nil), nil
	})}
	m.HistoryWriteAdmission = func(ctx context.Context, required int) error {
		requirements = append(requirements, required)
		return ErrHistoryAdmission
	}
	result, err := m.SyncSaved(context.Background(), feed.SourceID)
	if !errors.Is(err, ErrHistoryAdmission) || !result.NotModified || result.Imported != 0 || result.Cursor != 32 || !reflect.DeepEqual(requirements, []int{1, 3}) {
		t.Fatal("cached incoming XHTTP bypassed admission or advanced its cursor", result, err, requirements)
	}
	afterNodes, err := nodes.ExportPrivate(context.Background())
	if err != nil || !bytes.Equal(beforeNodes.Content, afterNodes.Content) {
		t.Fatal("refused cached page changed candidates/origins/history", err)
	}
	after, err := os.ReadFile(filepath.Join(path, FileName))
	if err != nil || !bytes.Equal(reservation, after) || !reflect.DeepEqual(beforeBodies, historyFeedBodies(t, path)) {
		t.Fatal("refused cached page promoted state or changed its immutable body", err)
	}
	state := m.List()[0]
	if state.Cursor != beforeState.Cursor || state.OriginExpiresAt != beforeState.OriginExpiresAt || state.LastSuccessAt != beforeState.LastSuccessAt {
		t.Fatal("refused cached page extended prior authority")
	}
}
