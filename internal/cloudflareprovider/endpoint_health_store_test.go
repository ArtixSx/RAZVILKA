package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func healthStoreFixture(t *testing.T) (*Store, string, Account, CandidatePreview, ScanReport, time.Time) {
	t.Helper()
	candidate, err := (Registrar{
		API:    &mockRegistrationAPI{result: validRegistrationResponse()},
		Random: bytes.NewReader(bytes.Repeat([]byte{43}, 64)),
	}).NewCandidate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	store, path := privateStore(t)
	account, err := store.ImportCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	var preview CandidatePreview
	if err := store.WithWireGuardCandidate(context.Background(), account.ID, CandidateOptions{}, func(_ context.Context, candidate WireGuardCandidate) error {
		preview = candidate.Public()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := EvaluateScanReport([]ScanAttempt{
		validScanAttempt(t, preview, now.Add(-3*time.Second)),
		validScanAttempt(t, preview, now.Add(-time.Second)),
	}, now, 5*time.Minute)
	return store, path, account, preview, report, now
}

func TestEndpointHealthJournalSurvivesRestartAndExpiresClosed(t *testing.T) {
	store, path, account, _, report, now := healthStoreFixture(t)
	health, err := store.RecordEndpointHealth(context.Background(), account.ID, CandidateOptions{}, report)
	if err != nil || !health.Selectable(now) {
		t.Fatalf("record health=%+v err=%v", health, err)
	}
	info, err := os.Stat(filepath.Join(path, endpointHealthFile))
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private journal permissions: %v err=%v", info, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, exists, err := reopened.LoadEndpointHealth(context.Background(), account.ID, CandidateOptions{}, now.Add(time.Second))
	if err != nil || !exists || !loaded.Selectable(now.Add(time.Second)) || loaded.RoutePathID != report.RoutePathID {
		t.Fatalf("loaded health=%+v exists=%v err=%v", loaded, exists, err)
	}
	if expired, exists, err := reopened.LoadEndpointHealth(context.Background(), account.ID, CandidateOptions{}, loaded.EvidenceValidUntil); err != nil || !exists || expired.Selectable(loaded.EvidenceValidUntil) {
		t.Fatalf("expired health=%+v exists=%v err=%v", expired, exists, err)
	}
	encoded, _ := json.Marshal(loaded)
	var public EndpointHealth
	_ = json.Unmarshal(encoded, &public)
	if public.Selectable(now) {
		t.Fatal("public JSON recreated persisted trust")
	}
}

func TestEndpointHealthJournalDoesNotCrossCandidateIdentity(t *testing.T) {
	store, _, account, _, report, now := healthStoreFixture(t)
	if _, err := store.RecordEndpointHealth(context.Background(), account.ID, CandidateOptions{}, report); err != nil {
		t.Fatal(err)
	}
	for _, options := range []CandidateOptions{{MTU: 1360}, {EndpointIndex: 1}} {
		if health, exists, err := store.LoadEndpointHealth(context.Background(), account.ID, options, now); err != nil || exists || health.valid {
			t.Fatalf("health crossed identity: %+v exists=%v err=%v", health, exists, err)
		}
	}
	reportJSON, _ := json.Marshal(report)
	var forged ScanReport
	_ = json.Unmarshal(reportJSON, &forged)
	if _, err := store.RecordEndpointHealth(context.Background(), account.ID, CandidateOptions{}, forged); !errors.Is(err, ErrEndpointHealth) {
		t.Fatal("public report was persisted", err)
	}
}

func TestEndpointHealthJournalRejectsUnknownOrCorruptState(t *testing.T) {
	store, path, account, _, report, _ := healthStoreFixture(t)
	if _, err := store.RecordEndpointHealth(context.Background(), account.ID, CandidateOptions{}, report); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, endpointHealthFile))
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] = ','
	data = append(data, []byte(`"unknown":true}`)...)
	if err := os.WriteFile(filepath.Join(path, endpointHealthFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrEndpointHealthStore) {
		t.Fatal("corrupt journal did not block Provider startup", err)
	}
}

func TestEndpointHealthJournalPersistsCooldownAndResetsIt(t *testing.T) {
	store, _, account, preview, _, now := healthStoreFixture(t)
	failure := validScanAttempt(t, preview, now.Add(-time.Second))
	failure.CleanupConfirmed = false
	failedReport := EvaluateScanReport([]ScanAttempt{failure}, now, time.Minute)
	health, err := store.RecordEndpointHealth(context.Background(), account.ID, CandidateOptions{}, failedReport)
	if err != nil || health.State != EndpointHealthCooldown || health.ConsecutiveFailures != 1 || health.Score != 0 {
		t.Fatalf("cooldown=%+v err=%v", health, err)
	}
	loaded, exists, err := store.LoadEndpointHealth(context.Background(), account.ID, CandidateOptions{}, now.Add(time.Second))
	if err != nil || !exists || loaded.State != EndpointHealthCooldown || loaded.Selectable(now.Add(time.Second)) {
		t.Fatalf("loaded cooldown=%+v exists=%v err=%v", loaded, exists, err)
	}
}
