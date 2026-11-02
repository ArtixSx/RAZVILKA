//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual two original filesystem writers, without a native/source issuer.
// An incomplete capture pair cannot mint the token, even with shaped local
// cleanup handles. No pathname is reopened or adopted as original custody.
func TestDomainFailureUnpublishedPreparationRequiresBothOriginalACKs(t *testing.T) {
	k, ctx := domainTCPKeeperFilesFixture(t)
	c, s := k.cursor, k.cursor.scope
	p := &XrayDomainTCPExecutionResource{scope: s, records: k.records}
	p.self = p
	control := &operationgate.ControlEpochReview{}
	p.material = &XrayDomainTCPOperationMaterial{resource: p, control: control}
	p.material.self = p.material
	capture := &domainTCPCaptureExecutionResource{process: p, retirementDetached: true}
	capture.self = capture
	baseline := &syntheticBaselineExecutionResource{inspector: &syntheticBaselineKernelInspector{}}
	baseline.self = baseline
	r := &domainTCPFailureCleanup{cursor: c, resource: p, capture: capture, captureDetached: true, imageStage: "capture", control: control, cleanup: &operationgate.ExclusiveCleanupReview{}}
	r.self = r
	c.cleanup = r
	c.failedCustody.Store(true)
	r.ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, r)
	r.active.Store(true)
	defer r.active.Store(false)
	if err := r.local(r.ctx, p); err != nil {
		t.Fatal("invalid local comparison fixture", err)
	}
	o := &DomainTCPOriginalScope{}
	o.self = o
	before := [2]os.FileInfo{}
	k.records.mu.Lock()
	copy(before[:], k.records.infos[:])
	k.records.mu.Unlock()
	if r.freezeUnpublishedPreparation(r.ctx, o, capture, baseline) == nil || o.unpublishedPreparation != nil {
		t.Fatal("missing ACK minted preparation")
	}
	// A true first-writer-only cut: accepted new FD0, original FD1. An ACK
	// flag cannot substitute for the two current original writer images.
	next := *s.execution
	next.Error = "original filesystem-only partial capture image"
	*s.execution = next
	image, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.records.publishOriginalDurable(0, image, syncDataplaneJournalDirectory); err != nil {
		t.Fatal(err)
	}
	r.imageACK = true
	if err := r.local(r.ctx, p); err != nil {
		t.Fatal("partial image broke local comparison fixture", err)
	}
	if err := k.records.current(r.ctx, true); err == nil {
		t.Fatal("actual first-writer-only pair was accepted as equal")
	}
	if r.freezeUnpublishedPreparation(r.ctx, o, capture, baseline) == nil || o.unpublishedPreparation != nil {
		t.Fatal("partial original pair minted preparation")
	}
	k.records.mu.Lock()
	defer k.records.mu.Unlock()
	if !bytes.Equal(k.records.images[0], image) || !bytes.Equal(k.records.images[1], k.image) || !os.SameFile(before[1], k.records.infos[1]) {
		t.Fatal("refused preparation altered or closed accepted writer custody")
	}
}
