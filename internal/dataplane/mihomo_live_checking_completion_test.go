package dataplane

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestMihomoActiveCheckingOriginalDocumentaryCompletion(t *testing.T) {
	_, _, r, e := mihomoLiveRecordModel(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r.control, err = gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer r.control.Close()
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	s := r.scope
	s.retained = true
	bound, end, err := r.operation(held, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	before, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	h := ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("c", 64), PlanID: e.PlanID, PlanDigest: e.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(before), Phase: "checking"}
	c := &mihomoLiveHealthCheck{owner: r, cleanup: cleanup, before: before, header: h, open: true}
	c.self = c
	r.healthCheck = c
	e.State, e.FinishedAt, e.MihomoLiveHealthOperation = mihomoActiveCheckingState, "", &h
	s.mu.Lock()
	err = c.publishLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal("initial", err)
	}
	if err := validateExecutionResources(*e, false); err != nil {
		t.Fatal("pure initial", err)
	}
	if !reflect.DeepEqual(e.Resources[0].MihomoLive, &r.definition) {
		cloned := r.definition.Clone()
		t.Fatalf("definition drift: matches original constructor clone=%t", reflect.DeepEqual(e.Resources[0].MihomoLive, &cloned))
	}
	s.mu.Lock()
	err = r.localRecord(bound, true)
	s.mu.Unlock()
	if err != nil {
		t.Fatal("original record", err)
	}
	if err := c.complete(bound); err != nil {
		t.Fatal("completion", err)
	}
	if r.healthCheck != nil || s.pending || c.open || e.State != "committed" || e.MihomoLiveHealthOperation.Phase != "settled" {
		t.Fatal("documentary completion did not retain typed history")
	}
}
