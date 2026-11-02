package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A COMMON publication model with real directory/file owners. It cannot
// supply a source, original process, control lease, TUN or service evidence.
func mihomoLiveRecordModel(t *testing.T) (*Manager, *MihomoProbeAdapter, *mihomoLiveResource, *Execution) {
	t.Helper()
	d := mihomoLiveDefinitionFixture(t)
	d.NativeHome = mihomoLiveHomeFixture(t)
	d.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: strings.Repeat("a", 64)}
	digest, _ := d.FrozenDigest()
	e := &Execution{PlanID: d.Plan.PlanID, Digest: d.Plan.Digest, State: "committed", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	stateRoot := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(stateRoot)
	a := &MihomoProbeAdapter{}
	a.self = a
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	ctx = WithReviewGuard(ctx, func(c context.Context) error { return c.Err() })
	root := filepath.Join(m.StateRoot, "transactions", e.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	s, err := m.newExecutionResourceScope(ctx, d.Plan, "mihomo", e, root)
	if err != nil {
		t.Fatal(err)
	}
	records, err := newXraySelectedTCPRecords(s)
	if err != nil {
		t.Fatal(err)
	}
	r := &mihomoLiveResource{adapter: a, scope: s, definition: d, id: "ml-" + strings.Repeat("1", 32), records: records}
	r.self = r
	s.mihomoLive = r
	a.livePending = r
	row := d.Clone()
	e.Resources = []ExecutionResource{{ID: r.id, Kind: "mihomo-live", State: "active", Phase: "active", Generation: d.Profile.ConfigSHA256, EffectsDigest: digest, MihomoLive: &row}}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.publishRecords(data); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.cancel(); _ = records.close(); _ = s.owned.Close() })
	return m, a, r, e
}

func TestMihomoLiveRetentionClosingRefusalPreservesOriginalRollbackImage(t *testing.T) {
	m, a, r, e := mihomoLiveRecordModel(t)
	a.livePending = nil // Modeled closing slot drift; no native process exists.
	if err := m.retainOriginalMihomo(r.scope, false); err == nil {
		t.Fatal("changed original slot accepted")
	}
	if r.scope.execution != e || r.scope.retained {
		t.Fatal("refused handoff detached rollback image")
	}
	e.Error = "original compensation still owns this image"
	if r.scope.execution.Error != e.Error {
		t.Fatal("rollback wrote a detached image")
	}
}

func TestMihomoLiveRetentionDetachesDTOAndRevokesOldApply(t *testing.T) {
	m, a, r, e := mihomoLiveRecordModel(t)
	if err := m.retainOriginalMihomo(r.scope, false); err != nil {
		t.Fatal(err)
	}
	if r.scope.execution == e || !r.scope.retained || r.scope.pending || a.liveActive != r || a.livePending != nil || r.scope.ctx.Err() == nil || r.scope.observationOpen.Load() {
		t.Fatal("original handoff incomplete")
	}
	e.Resources[0].MihomoLive.Plan.Routes[0].CIDRs[0] = "9.9.9.0/24"
	if r.scope.execution.Resources[0].MihomoLive.Plan.Routes[0].CIDRs[0] != "1.1.1.0/24" {
		t.Fatal("caller DTO changed retained intent")
	}
}

func TestMihomoLiveNewApplyCannotOverwriteOriginalLatest(t *testing.T) {
	m, _, r, _ := mihomoLiveRecordModel(t)
	if err := m.retainOriginalMihomo(r.scope, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.StateRoot, "latest-execution.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = m.Apply(ctx, r.definition.Plan, func() (func() error, error) { t.Fatal("replacement reached commit"); return nil, nil })
	if !errors.Is(err, ErrNetworkPolicyReplacement) {
		t.Fatal("new Apply passed original custody", err)
	}
	after, err := os.ReadFile(path)
	closing, statErr := os.Stat(path)
	if err != nil || statErr != nil || !os.SameFile(info, closing) || !bytes.Equal(before, after) {
		t.Fatal("refused Apply replaced original writer", err, statErr)
	}
}

func TestMihomoLiveRetainedWireRoundTripStillRequiresOriginalInodes(t *testing.T) {
	m, _, r, _ := mihomoLiveRecordModel(t)
	if err := m.retainOriginalMihomo(r.scope, false); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r.scope.execution)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Execution
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := m.checkRetainedMihomoRecord(decoded); err != nil {
		t.Fatal("same original wire record rejected", err)
	}
	if err := r.records.root.WriteAtomic("latest-execution.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.checkRetainedMihomoRecord(decoded); err == nil {
		t.Fatal("equal-byte foreign inode adopted")
	}
}
