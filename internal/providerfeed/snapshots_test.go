package providerfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func pageFeed(count int) string {
	var rows []string
	for i := range count {
		rows = append(rows, strings.Replace(goodURI, "node.example.org", fmt.Sprintf("node%03d.example.org", i), 1))
	}
	return strings.Join(rows, "\n")
}
func savePagedFeed(t *testing.T, m *Manager) State {
	t.Helper()
	s, err := m.Save(context.Background(), "", SaveRequest{Request: Request{URL: "https://feed.example.org/private-page-token", Limit: 32}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSnapshotCursorReaches33rdAfterRestart304WithoutExtendingProof(t *testing.T) {
	m, nodes, path := persistentManager(t)
	s := savePagedFeed(t, m)
	setResponse(m, 200, pageFeed(70), http.Header{"Etag": []string{`"v1"`}})
	first, err := m.SyncSaved(context.Background(), s.SourceID)
	if err != nil || len(first.NodeIDs) != 32 || first.Cursor != 32 || first.SnapshotEntries != 70 {
		t.Fatal(first, err)
	}
	_, err = nodes.RecordCheck(context.Background(), first.NodeIDs[0], nodestore.CheckRecord{ProbeID: "page-test", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + first.NodeIDs[0], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), HTTPStatus: 200}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := nodes.Snapshot(context.Background(), testTime.Add(2*time.Hour))
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
		if r.Header.Get("If-None-Match") != `"v1"` {
			t.Error("restart lost validated snapshot")
		}
		return response(304, "", nil), nil
	})}
	second, err := m.SyncSaved(context.Background(), s.SourceID)
	if err != nil || !second.NotModified || len(second.NodeIDs) != 32 || second.Cursor != 64 || !second.OriginExpiresAt.Equal(first.OriginExpiresAt) {
		t.Fatal(second, err)
	}
	for _, id := range second.NodeIDs {
		for _, old := range first.NodeIDs {
			if id == old {
				t.Fatal("repeated prefix instead of second page")
			}
		}
	}
	after, _ := nodes.Snapshot(context.Background(), testTime.Add(2*time.Hour))
	if len(after.Nodes) != 64 {
		t.Fatal("33rd entry not retained")
	}
	for _, node := range after.Nodes {
		if len(node.Origins) != 1 || !node.Origins[0].ExpiresAt.Equal(first.OriginExpiresAt) {
			t.Fatal("304 extended origin")
		}
		if node.ID == first.NodeIDs[0] {
			for _, old := range before.Nodes {
				if old.ID == node.ID {
					a, _ := json.Marshal(old.Health)
					b, _ := json.Marshal(node.Health)
					if string(a) != string(b) {
						t.Fatal("304 changed health")
					}
					if !old.Origins[0].ReceivedAt.Equal(node.Origins[0].ReceivedAt) {
						t.Fatal("partial page touched old origin")
					}
				}
			}
		}
	}
	third, err := m.SyncSaved(context.Background(), s.SourceID)
	if err != nil || third.Cursor != 70 || len(third.NodeIDs) != 6 {
		t.Fatal(third, err)
	}
	beforeBytes, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "nodes", "nodes.private.json"))
	last, err := m.SyncSaved(context.Background(), s.SourceID)
	afterBytes, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "nodes", "nodes.private.json"))
	if err != nil || last.Imported != 0 || last.Cursor != 70 || string(beforeBytes) != string(afterBytes) {
		t.Fatal("exhausted 304 repeated import", last, err)
	}
	public, _ := json.Marshal(m.List())
	if strings.Contains(string(public), "private-page-token") || strings.Contains(string(public), "11111111") {
		t.Fatal("private cache leaked")
	}
}

func TestSnapshotNewDigestRestartsCursorAndRemovesOnlyOwnedOrphans(t *testing.T) {
	m, nodes, path := persistentManager(t)
	s := savePagedFeed(t, m)
	setResponse(m, 200, pageFeed(40), nil)
	if _, err := m.SyncSaved(context.Background(), s.SourceID); err != nil {
		t.Fatal(err)
	}
	old := snapshotName(s.SourceID, m.states[s.SourceID].snapshot)
	foreign := filepath.Join(path, snapshotDirectory, "notes.txt")
	if err := os.WriteFile(foreign, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	// New ordering and a new first candidate form a new immutable generation.
	setResponse(m, 200, strings.Replace(pageFeed(40), "node000.example.org", "new-generation.example.org", 1), nil)
	r, err := m.SyncSaved(context.Background(), s.SourceID)
	if err != nil || r.Cursor != 32 {
		t.Fatal(r, err)
	}
	if _, err := os.Stat(filepath.Join(path, old)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old snapshot retained after commit")
	}
	if raw, _ := os.ReadFile(foreign); string(raw) != "retain" {
		t.Fatal("unrelated file removed")
	}
	view, _ := nodes.Snapshot(context.Background(), testTime)
	if len(view.Nodes) != 33 {
		t.Fatal("new digest lost retained partial origins")
	}
	state, err := m.Saved(s.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(context.Background(), s.SourceID, state.Revision); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(path, snapshotDirectory))
	if len(entries) != 1 || entries[0].Name() != "notes.txt" {
		t.Fatal("delete did not remove own cache")
	}
	view, _ = nodes.Snapshot(context.Background(), testTime)
	if len(view.Nodes) != 33 {
		t.Fatal("subscription removal deleted referenced node material")
	}
}

func TestSnapshotCorruptionAndExpiryNeverAuthorize304(t *testing.T) {
	for _, failure := range []string{"missing", "corrupt", "expired", "backward-clock", "permissions"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "permissions" && runtime.GOOS == "windows" {
				t.Skip("POSIX private permissions")
			}
			m, nodes, path := persistentManager(t)
			s := savePagedFeed(t, m)
			setResponse(m, 200, pageFeed(40), http.Header{"Etag": []string{`"v1"`}})
			if _, err := m.SyncSaved(context.Background(), s.SourceID); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, snapshotName(s.SourceID, m.states[s.SourceID].snapshot))
			switch failure {
			case "missing":
				os.Remove(file)
			case "corrupt":
				os.WriteFile(file, []byte("changed"), 0600)
			case "expired":
				m.now = func() time.Time { return testTime.Add(25 * time.Hour) }
			case "backward-clock":
				m.now = func() time.Time { return testTime.Add(-time.Minute) }
			case "permissions":
				os.Chmod(file, 0644)
			}
			m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("If-None-Match") != "" {
					t.Error("unsafe conditional request")
				}
				return response(304, "", nil), nil
			})}
			if _, err := m.SyncSaved(context.Background(), s.SourceID); err == nil {
				t.Fatal("unusable cache accepted 304")
			}
			view, _ := nodes.Snapshot(context.Background(), testTime)
			if len(view.Nodes) != 32 {
				t.Fatal("failure changed installed nodes")
			}
		})
	}
}

func TestSnapshotDiskQuotaAndSymlinkRefuseBeforeImport(t *testing.T) {
	for _, kind := range []string{"quota", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			m, nodes, path := persistentManager(t)
			s := savePagedFeed(t, m)
			if err := os.Mkdir(filepath.Join(path, snapshotDirectory), 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "quota" {
				f, err := os.Create(filepath.Join(path, snapshotDirectory, "keep.bin"))
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(maxSnapshotDiskBytes); err != nil {
					t.Fatal(err)
				}
				f.Close()
			} else {
				outside := filepath.Join(t.TempDir(), "foreign")
				os.WriteFile(outside, []byte("retain"), 0600)
				if err := os.Symlink(outside, filepath.Join(path, snapshotDirectory, "foreign-link")); err != nil {
					t.Skip("symlink privilege unavailable")
				}
			}
			setResponse(m, 200, pageFeed(40), nil)
			if _, err := m.SyncSaved(context.Background(), s.SourceID); err == nil {
				t.Fatal("unsafe/full cache imported nodes")
			}
			view, _ := nodes.Snapshot(context.Background(), testTime)
			if len(view.Nodes) != 0 {
				t.Fatal("failure occurred after import")
			}
		})
	}
}

func TestParseWindowCrossesInvalidAndDuplicateEntriesWithoutSkippingLaterNodes(t *testing.T) {
	data := []byte(goodURI + "\n" + goodURI + "\ninvalid\n" + strings.Replace(goodURI, "node.example.org", "later.example.org", 1))
	first, err := parseWindow(context.Background(), data, "uri-lines", 1, 0)
	if err != nil || first.nextCursor != 1 {
		t.Fatal(first.nextCursor, err)
	}
	second, err := parseWindow(context.Background(), data, "uri-lines", 2, first.nextCursor)
	if err != nil || second.nextCursor != 4 || second.accepted != 2 || second.rejected != 1 {
		t.Fatal("cursor did not progress", second.nextCursor, err)
	}
	if _, err := parseWindow(context.Background(), data, "uri-lines", 1, 5); !errors.Is(err, ErrRequest) {
		t.Fatal("out of range cursor accepted")
	}
}

func TestSnapshotFreshResponseRepairsOnlyReferencedCacheWithinQuota(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			m, nodes, path := persistentManager(t)
			s := savePagedFeed(t, m)
			raw := pageFeed(40)
			setResponse(m, 200, raw, http.Header{"Etag": []string{`"v1"`}})
			if _, err := m.SyncSaved(context.Background(), s.SourceID); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, snapshotName(s.SourceID, m.states[s.SourceID].snapshot))
			if err := os.WriteFile(file, []byte("bad"), 0600); err != nil {
				t.Fatal(err)
			}
			if full {
				f, err := os.Create(filepath.Join(path, snapshotDirectory, "unrelated.bin"))
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(maxSnapshotDiskBytes - 3)
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("If-None-Match") != "" {
					t.Error("corrupt cache sent validator")
				}
				return response(200, raw, nil), nil
			})}
			r, err := m.SyncSaved(context.Background(), s.SourceID)
			if full {
				if !errors.Is(err, ErrSize) {
					t.Fatal("repair exceeded quota", err)
				}
				if data, _ := os.ReadFile(file); string(data) != "bad" {
					t.Fatal("failed repair replaced cache")
				}
			} else {
				if err != nil || r.Cursor != 32 {
					t.Fatal("fresh repair must restart cursor", r, err)
				}
				if data, _ := os.ReadFile(file); string(data) != raw {
					t.Fatal("fresh body not repaired")
				}
			}
			view, _ := nodes.Snapshot(context.Background(), testTime)
			if len(view.Nodes) != 32 {
				t.Fatal("corrupt cursor granted additional imports")
			}
		})
	}
}

func TestParseJSONWindowsReachLaterCandidates(t *testing.T) {
	var profiles []json.RawMessage
	var keys []map[string]string
	for _, uri := range strings.Split(pageFeed(40), "\n") {
		parsed, err := providerprofile.ParseURI(uri)
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if err := json.Unmarshal(parsed.Config, &p); err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p.Outbounds[0])
		keys = append(keys, map[string]string{"key": uri})
	}
	profile, _ := json.Marshal(profiles)
	keyDocument, _ := json.Marshal(map[string]any{"world": map[string]any{"top10": keys}})
	for format, raw := range map[string][]byte{"profile": profile, "keys-json": keyDocument} {
		t.Run(format, func(t *testing.T) {
			first, err := parseWindow(context.Background(), raw, format, 32, 0)
			if err != nil || first.accepted != 32 || first.nextCursor != 32 {
				t.Fatal(first.nextCursor, err)
			}
			last, err := parseWindow(context.Background(), raw, format, 32, first.nextCursor)
			if err != nil || last.accepted != 8 || last.nextCursor != 40 {
				t.Fatal(last.nextCursor, err)
			}
			for _, a := range first.materials {
				for _, b := range last.materials {
					if string(a) == string(b) {
						t.Fatal("repeated first page")
					}
				}
			}
		})
	}
}

func TestSnapshotCanceledOrDeletedDuringFetchNeverImportsNextPage(t *testing.T) {
	for _, action := range []string{"cancel", "delete"} {
		t.Run(action, func(t *testing.T) {
			m, nodes, _ := persistentManager(t)
			s := savePagedFeed(t, m)
			setResponse(m, 200, pageFeed(40), http.Header{"Etag": []string{`"v1"`}})
			if _, err := m.SyncSaved(context.Background(), s.SourceID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if action == "cancel" {
					cancel()
				} else {
					current, err := m.Saved(s.SourceID)
					if err != nil {
						t.Fatal(err)
					}
					if err := m.Delete(context.Background(), s.SourceID, current.Revision); err != nil {
						t.Fatal(err)
					}
				}
				return response(304, "", nil), nil
			})}
			if _, err := m.SyncSaved(ctx, s.SourceID); err == nil {
				t.Fatal("obsolete page accepted")
			}
			view, _ := nodes.Snapshot(context.Background(), testTime)
			if len(view.Nodes) != 32 {
				t.Fatal("obsolete page imported")
			}
		})
	}
}
