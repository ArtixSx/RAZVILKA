package providerfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func persistentManager(t *testing.T) (*Manager, *nodestore.Store, string) {
	t.Helper()
	root := t.TempDir()
	nodesDir := filepath.Join(root, "nodes")
	feedsDir := filepath.Join(root, "feeds")
	for _, dir := range []string{nodesDir, feedsDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	nodes, err := nodestore.Open(nodesDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodes.Close() })
	m, err := Open(nodes, feedsDir)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return testTime }
	t.Cleanup(func() { m.Close() })
	return m, nodes, feedsDir
}
func saveFeed(t *testing.T, m *Manager, enabled bool) State {
	t.Helper()
	state, err := m.Save(context.Background(), "", SaveRequest{Request: Request{URL: "https://feed.example.org/private-path-token?secret=query-token", Limit: 128}, Name: "Моя подписка", Enabled: enabled})
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func TestSavedSubscriptionIsDurableWithoutFetchAndPublicViewsNeverContainTokens(t *testing.T) {
	m, nodes, path := persistentManager(t)
	var fetched atomic.Int32
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fetched.Add(1)
		return nil, errors.New("secret network error")
	})}
	state := saveFeed(t, m, true)
	if fetched.Load() != 0 || !state.Saved || !state.Enabled || state.RefreshIntervalMinutes != 360 || state.Limit != 128 || state.Revision != 1 {
		t.Fatal("saving fetched a source or did not retain settings")
	}
	if _, err := Open(nodes, path); err == nil {
		t.Fatal("second writer acquired private subscriptions")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(nodes, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	views := reopened.List()
	if len(views) != 1 || views[0].Name != "Моя подписка" || !views[0].Enabled {
		t.Fatal("restart lost saved subscription")
	}
	public, _ := json.Marshal(views)
	for _, secret := range []string{"private-path-token", "query-token", "secret network error"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("private source escaped into public state")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", SaveRequest{Request: Request{URL: "https://example.org/query-token"}}, m), "query-token") {
		t.Fatal("formatted request leaked URL")
	}
}

func TestPresetRefreshDefaultsOnlyNewSubscriptionsWithoutExplicitInterval(t *testing.T) {
	for _, preset := range Builtins() {
		want := DefaultRefreshMinutes
		if preset.ID == "kort0881-ru-sni" {
			want = 120
		}
		if preset.DefaultRefreshIntervalMinutes != want {
			t.Fatalf("preset %s refresh default = %d", preset.ID, preset.DefaultRefreshIntervalMinutes)
		}
		t.Run(preset.ID, func(t *testing.T) {
			m, nodes, path := persistentManager(t)
			state, err := m.Save(context.Background(), "", SaveRequest{Request: Request{PresetID: preset.ID}, Enabled: true})
			if err != nil || state.RefreshIntervalMinutes != want {
				t.Fatalf("new preset interval = %d, err=%v", state.RefreshIntervalMinutes, err)
			}
			state, err = m.Save(context.Background(), state.SourceID, SaveRequest{Revision: state.Revision, Name: "Мой интервал", RefreshIntervalMinutes: 1440, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			state, err = m.Save(context.Background(), state.SourceID, SaveRequest{Revision: state.Revision, Enabled: false})
			if err != nil || state.RefreshIntervalMinutes != 1440 || state.Name != "Мой интервал" {
				t.Fatal("editing reset saved options to preset defaults")
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(nodes, path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if state := reopened.List()[0]; state.RefreshIntervalMinutes != 1440 || state.Enabled {
				t.Fatal("restart reset saved options")
			}
		})
	}
	t.Run("custom URL does not inherit preset", func(t *testing.T) {
		m, _, _ := persistentManager(t)
		preset := Builtins()[len(Builtins())-1]
		state, err := m.Save(context.Background(), "", SaveRequest{Request: Request{URL: preset.URL}})
		if err != nil || state.RefreshIntervalMinutes != DefaultRefreshMinutes {
			t.Fatal("custom URL inherited preset default")
		}
	})
	t.Run("explicit new interval", func(t *testing.T) {
		m, _, _ := persistentManager(t)
		state, err := m.Save(context.Background(), "", SaveRequest{Request: Request{PresetID: "kort0881-ru-sni"}, RefreshIntervalMinutes: 60})
		if err != nil || state.RefreshIntervalMinutes != 60 {
			t.Fatal("preset overrode explicit new interval")
		}
	})
}
func TestSavedSubscriptionRevisionPauseDeleteAndCancellationPreserveImportedNodes(t *testing.T) {
	m, nodes, path := persistentManager(t)
	state := saveFeed(t, m, true)
	setResponse(m, 200, goodURI, nil)
	if _, err := m.SyncSaved(context.Background(), state.SourceID); err != nil {
		t.Fatal(err)
	}
	beforeNodes, err := nodes.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(path, FileName))
	for _, req := range []SaveRequest{{Revision: state.Revision + 1}, {Revision: state.Revision, Request: Request{URL: "https://other.example.org/new-token"}}, {Revision: state.Revision, RefreshIntervalMinutes: 1}} {
		if _, err := m.Save(context.Background(), state.SourceID, req); err == nil {
			t.Fatal("invalid edit accepted")
		}
		after, _ := os.ReadFile(filepath.Join(path, FileName))
		if string(after) != string(before) {
			t.Fatal("rejected edit changed durable state")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Save(canceled, state.SourceID, SaveRequest{Revision: state.Revision}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled save accepted")
	}
	paused, err := m.Save(context.Background(), state.SourceID, SaveRequest{Revision: state.Revision, Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if paused.Enabled || !paused.NextRefreshAt.IsZero() || len(m.Due(testTime.Add(48*time.Hour))) != 0 {
		t.Fatal("paused source remains scheduled")
	}
	if err := m.Delete(context.Background(), state.SourceID, paused.Revision); err != nil {
		t.Fatal(err)
	}
	afterNodes, _ := nodes.ExportPrivate(context.Background())
	if beforeNodes.SHA256 != afterNodes.SHA256 {
		t.Fatal("deleting subscription changed nodes or evidence")
	}
	if len(m.List()) != 0 {
		t.Fatal("deleted subscription remains listed")
	}
}
func TestSavedRefreshRestartKeeps304PassiveAndOnlyAllowlistedCountryMetadata(t *testing.T) {
	m, nodes, path := persistentManager(t)
	state := saveFeed(t, m, true)
	uri := strings.Replace(goodURI, "private-label", "🇳🇱 Netherlands secret-credential-label", 1)
	setResponse(m, 200, uri, http.Header{"Etag": []string{`"private-validator"`}})
	result, err := m.SyncSaved(context.Background(), state.SourceID)
	if err != nil || len(result.NodeIDs) != 1 {
		t.Fatal("country import failed")
	}
	metadata := m.CountryMetadata()
	if metadata[result.NodeIDs[0]].Code != "NL" || metadata[result.NodeIDs[0]].Source != "publisher" {
		t.Fatal("country not attributed to publisher")
	}
	before, _ := nodes.ExportPrivate(context.Background())
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(nodes, path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.now = func() time.Time { return testTime.Add(6 * time.Hour) }
	r.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("If-None-Match") != `"private-validator"` {
			t.Fatal("restart lost exact-source validator")
		}
		return response(304, "", nil), nil
	})}
	got, err := r.SyncSaved(context.Background(), state.SourceID)
	if err != nil || !got.NotModified || !got.OriginExpiresAt.Equal(testTime.Add(OriginTTL)) {
		t.Fatal("304 changed origin TTL")
	}
	after, _ := nodes.ExportPrivate(context.Background())
	if before.SHA256 != after.SHA256 {
		t.Fatal("304 changed node evidence")
	}
	public, _ := json.Marshal(struct {
		Sources   []State
		Countries map[string]Country
	}{r.List(), r.CountryMetadata()})
	for _, secret := range []string{"secret-credential-label", "private-validator", "private-path-token", "11111111-1111-4111-8111-111111111111"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("private metadata escaped")
		}
	}
}

func TestCountryCollectionPresetMetadataPersistsWithoutInferringFromCustomURL(t *testing.T) {
	profile := `[{"type":"vless","tag":"vless-1104257579","server":"node.example.org","server_port":443,"uuid":"11111111-1111-4111-8111-111111111111","tls":{"enabled":true,"server_name":"node.example.org"}}]`
	for _, builtin := range []bool{true, false} {
		t.Run(fmt.Sprintf("builtin=%t", builtin), func(t *testing.T) {
			m, nodes, path := persistentManager(t)
			req := Request{PresetID: "au1rxx-nl", Limit: 16}
			if !builtin {
				resolved, err := resolve(req)
				if err != nil {
					t.Fatal(err)
				}
				req = Request{URL: resolved.url, Format: resolved.format, Limit: 16}
			}
			state, err := m.Save(context.Background(), "", SaveRequest{Request: req, Name: "Нидерланды", Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			setResponse(m, 200, profile, nil)
			result, err := m.SyncSaved(context.Background(), state.SourceID)
			if err != nil || len(result.NodeIDs) != 1 {
				t.Fatal("country collection import failed")
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(nodes, path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			metadata := reopened.CountryMetadata()
			if builtin {
				if metadata[result.NodeIDs[0]] != (Country{Code: "NL", Source: "publisher"}) {
					t.Fatal("known country collection lost its attributed label after restart")
				}
			} else if len(metadata) != 0 {
				t.Fatal("custom URL or display name inferred collection country")
			}
		})
	}
}

func TestCountryFullRefreshRetractsOnlyOwnAcceptedLabelsAndKeeps304FailureClaims(t *testing.T) {
	for _, otherSource := range []bool{false, true} {
		t.Run(fmt.Sprintf("other_source=%t", otherSource), func(t *testing.T) {
			m, _, _ := persistentManager(t)
			state := saveFeed(t, m, true)
			known := strings.Replace(goodURI, "private-label", "Netherlands [WS]", 1)
			setResponse(m, 200, known, http.Header{"Etag": []string{`"country-version"`}})
			first, err := m.SyncSaved(context.Background(), state.SourceID)
			if err != nil || len(first.NodeIDs) != 1 || m.CountryMetadata()[first.NodeIDs[0]].Code != "NL" {
				t.Fatal("country fixture import failed")
			}
			id := first.NodeIDs[0]
			if otherSource {
				setResponse(m, 200, known, nil)
				if _, err := m.Sync(context.Background(), Request{URL: "https://other.example.org/catalog"}); err != nil {
					t.Fatal(err)
				}
			}
			setResponse(m, 304, "", nil)
			if _, err := m.SyncSaved(context.Background(), state.SourceID); err != nil || m.CountryMetadata()[id].Code != "NL" {
				t.Fatal("304 retracted publisher label")
			}
			setResponse(m, 503, "private source failure", nil)
			if _, err := m.SyncSaved(context.Background(), state.SourceID); !errors.Is(err, ErrFetch) || m.CountryMetadata()[id].Code != "NL" {
				t.Fatal("failed fetch retracted last-good publisher label")
			}
			setResponse(m, 200, strings.Replace(goodURI, "private-label", "CF RU-SNI [TCP]", 1), nil)
			if _, err := m.SyncSaved(context.Background(), state.SourceID); err != nil {
				t.Fatal(err)
			}
			got, retained := m.CountryMetadata()[id]
			if otherSource && (!retained || got.Code != "NL") || !otherSource && retained {
				t.Fatal("full response failed to retract only its own ambiguous country label")
			}
		})
	}
}

func TestCountryRefreshKeepsLabelsOfPreviouslyImportedNodesMissingFromNewBatch(t *testing.T) {
	m, _, _ := persistentManager(t)
	state := saveFeed(t, m, true)
	setResponse(m, 200, strings.Replace(goodURI, "private-label", "Netherlands", 1), nil)
	first, err := m.SyncSaved(context.Background(), state.SourceID)
	if err != nil || len(first.NodeIDs) != 1 {
		t.Fatal("country fixture failed")
	}
	setResponse(m, 200, strings.Replace(goodURI, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1), nil)
	if _, err := m.SyncSaved(context.Background(), state.SourceID); err != nil || m.CountryMetadata()[first.NodeIDs[0]].Code != "NL" {
		t.Fatal("unseen retained node lost publisher label")
	}
}

func TestKortPresetUsesBoundedCollectionAndKeepsCandidatesUnproven(t *testing.T) {
	m, nodes, _ := testManager(t)
	var body strings.Builder
	for i := 0; i < 140; i++ {
		fmt.Fprintf(&body, "vless://%08x-1111-4111-8111-111111111111@node.example.org:443?security=tls&type=tcp#publisher-private-%d\n", i, i)
	}
	m.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt" {
			t.Fatal("preset did not use bounded RU SNI collection")
		}
		return response(200, body.String(), nil), nil
	})}
	result, err := m.Sync(context.Background(), Request{PresetID: "kort0881-ru-sni", Limit: 128})
	if err != nil || result.SourceID != "feed-kort0881-ru-sni" || result.TotalEntries != 140 || result.Imported != 128 || result.Omitted != 12 {
		t.Fatalf("bounded collection mismatch: imported=%d total=%d omitted=%d error=%v", result.Imported, result.TotalEntries, result.Omitted, err)
	}
	snapshot, err := nodes.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes) != 128 || len(snapshot.Groups) != 0 {
		t.Fatal("bounded collection storage mismatch")
	}
	for _, node := range snapshot.Nodes {
		if node.Health.State != "not_checked" || node.State != "quarantined" {
			t.Fatal("publisher collection granted local health")
		}
	}
	if len(m.CountryMetadata()) != 0 {
		t.Fatal("RU SNI classification became a measured or publisher country")
	}
}
func TestSavedSourceEditDuringFetchCannotImportStaleResponse(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	state := saveFeed(t, m, true)
	entered := make(chan struct{})
	resume := make(chan struct{})
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-resume
		return response(200, goodURI, nil), nil
	})}
	done := make(chan error, 1)
	go func() { _, err := m.SyncSaved(context.Background(), state.SourceID); done <- err }()
	<-entered
	if _, err := m.Save(context.Background(), state.SourceID, SaveRequest{Revision: state.Revision, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err := <-done; !errors.Is(err, ErrConflict) {
		t.Fatal("changed source accepted stale network response")
	}
	snapshot, err := nodes.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes) != 0 {
		t.Fatal("stale response imported nodes")
	}
}
func TestPrivateSubscriptionRestoreAddsPausedSourcesAndCanRollbackExactBytes(t *testing.T) {
	source, _, _ := persistentManager(t)
	saved := saveFeed(t, source, true)
	snapshot, err := source.ExportPrivateIfPresent(context.Background())
	if err != nil || snapshot == nil {
		t.Fatal(err)
	}
	target, _, path := persistentManager(t)
	session, err := target.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, err := session.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, err := session.MergeImage(context.Background(), *snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	view, err := target.Saved(saved.SourceID)
	if err != nil || view.Enabled || !view.NextRefreshAt.IsZero() || view.LastKnownGood {
		t.Fatal("restore started work or retained remote freshness")
	}
	session, err = target.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := session.CompareAndSwap(context.Background(), after, before); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, FileName)); !os.IsNotExist(err) || len(target.List()) != 0 {
		t.Fatal("rollback did not restore absent image")
	}
}
func TestSubscriptionImageCorruptionDoesNotResetSavedState(t *testing.T) {
	m, nodes, path := persistentManager(t)
	saveFeed(t, m, false)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, FileName)
	if err := os.WriteFile(file, []byte(`{"schema":1,"schema":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(nodes, path); err == nil {
		t.Fatal("corrupt store accepted")
	}
	data, _ := os.ReadFile(file)
	if string(data) != `{"schema":1,"schema":1}` {
		t.Fatal("corrupt evidence reset")
	}
}
func TestCountryInferenceRejectsAmbiguityAndNeverPassesPublisherText(t *testing.T) {
	for name, want := range map[string]string{"🇳🇱 Netherlands · key=private": "NL", "DE Германия": "DE", "Netherlands Germany": "", "secret-password": "", "🇬🇧 United Kingdom": "GB", "NL | DE": "", "🇦🇶 Antarctica": "AQ"} {
		if got := inferCountry(name); got != want {
			t.Fatalf("country interpretation mismatch got=%q want=%q", got, want)
		}
	}
}
func TestLargeJSONFeedTruncatesBeforeStoreAndReturnsTransparentCounts(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	var entries []map[string]any
	for i := 0; i < 200; i++ {
		entries = append(entries, map[string]any{"type": "vless", "tag": "🇳🇱 Netherlands private-name", "server": fmt.Sprintf("node%d.example.org", i), "server_port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "tls": map[string]any{"enabled": true}})
	}
	raw, _ := json.Marshal(map[string]any{"outbounds": entries})
	state, err := m.Save(context.Background(), "", SaveRequest{Request: Request{URL: "https://feed.example.org/catalog", Format: "profile", Limit: 128}})
	if err != nil {
		t.Fatal(err)
	}
	setResponse(m, 200, string(raw), nil)
	result, err := m.SyncSaved(context.Background(), state.SourceID)
	if err != nil || result.TotalEntries != 200 || result.Imported != 128 || result.Omitted != 72 {
		t.Fatalf("bounded selection counts wrong: imported=%d total=%d omitted=%d err=%v", result.Imported, result.TotalEntries, result.Omitted, err)
	}
	snapshot, _ := nodes.Snapshot(context.Background(), testTime)
	if len(snapshot.Nodes) != 128 {
		t.Fatal("retained selection differs from persisted candidates")
	}
	for _, country := range m.CountryMetadata() {
		if country.Code != "NL" {
			t.Fatal("unexpected country")
		}
	}
}

var _ restorejournal.Target = (*RestoreTarget)(nil)

func TestFeedCapacityIsExplicitAndDoesNotEvictAnyStoredNode(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	saved := saveFeed(t, m, false)
	for batch := 0; batch < 4; batch++ {
		var lines []string
		for i := 0; i < 128; i++ {
			lines = append(lines, fmt.Sprintf("vless://11111111-1111-4111-8111-111111111111@capacity%d.example.org:443?security=tls", batch*128+i))
		}
		if _, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, strings.Join(lines, "\n"), testTime, time.Hour, false); err != nil {
			t.Fatal(err)
		}
	}
	before, err := nodes.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	setResponse(m, 200, goodURI, nil)
	result, err := m.SyncSaved(context.Background(), saved.SourceID)
	if !errors.Is(err, ErrCapacity) || ErrorCode(err) != "FEED_CAPACITY" || result.Status != "capacity" {
		t.Fatal("capacity was not classified explicitly")
	}
	after, err := nodes.ExportPrivate(context.Background())
	if err != nil || before.SHA256 != after.SHA256 {
		t.Fatal("full-catalog refresh evicted or changed stored nodes")
	}
}
