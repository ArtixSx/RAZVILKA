//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

type nativePairedDraft struct {
	candidate strategylab.Candidate
	stateSHA  string
}

// Only the already running genuine old panel writes this draft. No state JSON,
// receipt, selection, native validation or service evidence is manufactured.
func nativePairedPublicDraftBefore(t *testing.T) *nativePairedDraft {
	t.Helper()
	mode := os.Getenv("RAZVILKA_PAIRED_NATIVE_HISTORY")
	if mode == "" {
		return nil
	}
	if mode != "draft" {
		t.Fatal("unknown paired draft scenario")
	}
	before := nativePairedDraftHTTP(t, http.MethodGet, "/api/v1/strategy-lab", nil, "")
	var baseline strategylab.Snapshot
	if json.Unmarshal(before, &baseline) != nil || len(baseline.Candidates) != 0 || len(baseline.Evidence) != 0 || len(baseline.Selections) != 0 {
		t.Fatal("old source draft baseline is not empty")
	}
	tokenPath := installpath.Config + "/admin.token"
	info, err := os.Lstat(tokenPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 32 || info.Size() > 256 {
		t.Fatal("private fixture source token unavailable")
	}
	file, err := os.Open(tokenPath)
	if err != nil {
		t.Fatal("private fixture source token unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 257))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(data) > 256 || int64(len(data)) != info.Size() || !os.SameFile(info, after) || after.Mode() != info.Mode() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("private fixture source token changed")
	}
	token := strings.TrimSpace(string(data))
	clear(data)
	// The bearer is held only in memory on a fixed loopback request; it is never
	// added to process args/logs or passed to the candidate bootstrap executable.
	body := []byte(`{"pool_id":"tcp-tls","name":"public paired retained draft","arguments":"--filter-tcp=443"}`)
	encoded := nativePairedDraftHTTP(t, http.MethodPost, "/api/v1/strategy-lab/candidates", body, token)
	var candidate strategylab.Candidate
	if json.Unmarshal(encoded, &candidate) != nil || candidate.ID == "" || candidate.PoolID != "tcp-tls" || candidate.Name != "public paired retained draft" || candidate.Arguments != "--filter-tcp=443" || candidate.Origin != "expert" || candidate.CreatedAt == "" || candidate.Validation.OK || candidate.Validation.Native {
		t.Fatal("old API did not author the exact unvalidated draft")
	}
	var snapshot strategylab.Snapshot
	if json.Unmarshal(nativePairedDraftHTTP(t, http.MethodGet, "/api/v1/strategy-lab", nil, ""), &snapshot) != nil {
		t.Fatal("old API snapshot unavailable")
	}
	nativePairedDraftSnapshot(t, snapshot, candidate)
	return &nativePairedDraft{candidate: candidate, stateSHA: nativePairedRestoreFileHash(t, installpath.State+"/strategy-lab.json")}
}

func nativePairedPublicDraftAfter(t *testing.T, draft *nativePairedDraft) {
	t.Helper()
	if draft == nil {
		return
	}
	path := installpath.State + "/strategy-lab.json"
	if nativePairedRestoreFileHash(t, path) != draft.stateSHA {
		t.Fatal("public pair rewrote original retained draft bytes")
	}
	reader, err := strategylab.New(path)
	if err != nil {
		t.Fatal("actual current StrategyLab reader refused retained draft", err)
	}
	nativePairedDraftSnapshot(t, reader.Snapshot(), draft.candidate)
	if nativePairedRestoreFileHash(t, path) != draft.stateSHA {
		t.Fatal("read-only retained draft check changed bytes")
	}
	// Public restore's existing protected-evidence assertion independently covers
	// current Stop/journals/unknown fences. This is not a live old-reader claim.
	t.Log("actual_public_pair_retained_draft preserved=true original_old_http_writer=true current_reader=true old_live_compatibility=false manual_selection=false")
}

func nativePairedDraftSnapshot(t *testing.T, snapshot strategylab.Snapshot, want strategylab.Candidate) {
	t.Helper()
	if snapshot.QuiescenceUnknown || len(snapshot.Candidates) != 1 || len(snapshot.Evidence) != 0 || len(snapshot.Selections) != 0 {
		t.Fatal("draft snapshot gained evidence/selection or lost original candidate")
	}
	got := snapshot.Candidates[0]
	if !reflect.DeepEqual(got, want) || got.Validation.OK || got.Validation.Native {
		t.Fatal("retained draft identity/content changed or gained readiness")
	}
	for _, summary := range snapshot.Summaries {
		if summary.Eligible {
			t.Fatal("unvalidated draft gained eligibility")
		}
	}
}

func nativePairedDraftHTTP(t *testing.T, method, path string, body []byte, token string) []byte {
	t.Helper()
	request, err := http.NewRequest(method, "http://127.0.0.1:8787"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal("fixture request construction failed")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("actual old fixture request failed")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	closeErr := response.Body.Close()
	expected := http.StatusOK
	if method == http.MethodPost {
		expected = http.StatusCreated
	}
	if readErr != nil || closeErr != nil || len(data) > 64<<10 || response.StatusCode != expected {
		t.Fatal("actual old fixture request refused", response.StatusCode)
	}
	return data
}
