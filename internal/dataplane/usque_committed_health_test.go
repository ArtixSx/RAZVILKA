package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUSQUECommittedHealthRunsFreshLiveProbeWithoutRestaging(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	f.activate()
	if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil {
		t.Fatal(err)
	}
	plan, err := Build(Input{Revision: 2, NetworkProfileID: f.plan.NetworkProfileID, Routes: f.plan.Routes, EngineConfigDrafts: f.plan.EngineDrafts,
		Engines: []Engine{{ID: "usque", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: HostState{IPCommand: true, TUN: true, SingBox: true}})
	if err != nil || !plan.Ready {
		t.Fatal("invalid fixture plan", err, plan.Blockers)
	}
	plan.State = "committed"
	m := New(filepath.Join(f.base, "manager"))
	if err := m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	// A stale editor draft must not replace the active, committed session.
	if _, err := f.a.Configs.Stage("usque", "main", `{"fixture":"unapplied"}`); err != nil {
		t.Fatal(err)
	}
	priorEvidence := f.produced
	priorEvidence.CheckedAt = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	priorEvidence.ValidUntil = time.Now().Add(-47 * time.Hour).UTC().Format(time.RFC3339Nano)
	prior, err := json.Marshal(priorEvidence.CanaryEvidence())
	if err != nil || os.WriteFile(f.a.evidencePath(), prior, 0600) != nil {
		t.Fatal("cannot stage expired historical receipt", err)
	}
	starts, stops, calls, canaries := f.processes.starts, f.processes.stops, f.liveCalls, f.canaryCalls
	mutations := len(receiptMutationCalls(f.runner.seen))
	start := time.Now()
	if err := m.CheckCommittedUSQUEHealth(f.ctx, plan, f.a.Configs); err != nil {
		t.Fatal(err)
	}
	f.proofWindow(start)
	current := f.evidence(f.a.evidencePath())
	if bytes.Equal(current, prior) || f.liveCalls != calls+1 || f.canaryCalls != canaries || f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.runner.seen)) != mutations {
		t.Fatal("observing committed USQUE replayed old evidence or changed runtime")
	}
	stale := plan
	stale.NetworkProfileID = "wan-123456789abd"
	if err := m.CheckCommittedUSQUEHealth(f.ctx, stale, f.a.Configs); !errors.Is(err, ErrReviewChanged) {
		t.Fatal("changed committed scope reached network probe", err)
	}
	if err := m.CheckCommittedUSQUEHealth(context.Background(), plan, f.a.Configs); err == nil {
		t.Fatal("missing original review passed")
	}
	f.processes.afterRunning = func(ProcessSpec, bool) { f.revoked = true }
	if err := m.CheckCommittedUSQUEHealth(f.ctx, plan, f.a.Configs); !errors.Is(err, ErrReviewChanged) || f.liveCalls != calls+1 || !bytes.Equal(current, f.evidence(f.a.evidencePath())) {
		t.Fatal("withdrawn review renewed a live receipt", err)
	}
	f.processes.afterRunning, f.revoked = nil, false
	material, err := f.a.Configs.Read("usque", "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(material.Path, []byte(`{"fixture":"changed-live-session"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckCommittedUSQUEHealth(f.ctx, plan, f.a.Configs); err == nil || f.liveCalls != calls+1 || !bytes.Equal(current, f.evidence(f.a.evidencePath())) {
		t.Fatal("changed live catalog session renewed evidence", err)
	}
}
