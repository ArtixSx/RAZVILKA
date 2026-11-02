//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Real authored journal descriptors/control; rows and completed native work
// are MODELED. This helper intentionally does not issue CheckWrite admission,
// a native child, a live health result or any new effect permission.
func mihomoCheckingWriterModel(t *testing.T) (*mihomoLiveHealthCheck, context.Context) {
	archive, held, cleanup := mihomoTransitArchiveFileModel(t)
	r, s := archive.owner, archive.owner.scope
	s.pending = false
	r.transitHistory = nil
	s.execution.Resources = cloneExecutionResources(s.execution.Resources[:1])
	s.issued = map[string]*executionTransitResource{}
	raw, err := json.Marshal(s.execution)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.publishRecords(raw); err != nil {
		t.Fatal(err)
	}
	ctx, end, err := r.operation(held, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	h := ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("b", 64), PlanID: s.execution.PlanID, PlanDigest: s.execution.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(raw), Phase: "checking"}
	c := &mihomoLiveHealthCheck{owner: r, cleanup: cleanup, before: raw, header: h, open: true}
	c.self = c
	r.healthCheck = c
	s.execution.MihomoLiveHealthOperation = &h
	s.execution.State, s.execution.FinishedAt = mihomoActiveCheckingState, ""
	return c, ctx
}

func TestMihomoActiveCheckingPartialACKKeepsOriginalWriter(t *testing.T) {
	c, ctx := mihomoCheckingWriterModel(t)
	r, s := c.owner, c.owner.scope
	cut := errors.New("model partial ACK cut")
	c.fault = func(step string) error {
		if step == "before-latest" {
			return cut
		}
		return nil
	}
	s.mu.Lock()
	err := c.publishLocked()
	s.mu.Unlock()
	if !errors.Is(err, cut) || s.failure != nil {
		t.Fatal("cut lost original recoverable writer", err, s.failure)
	}
	if r.records.current(ctx, false) != nil || r.records.current(ctx, true) == nil {
		t.Fatal("partial original images not distinguished")
	}
	c.fail()
	if !s.pending || c.open || !c.failed || r.healthCheck != c {
		t.Fatal("partial check dropped custody")
	}
	if r.scope.checkRetainedMihomoOperation(ctx, true) == nil {
		t.Fatal("failed writer retained forward grant")
	}
	// Model only the original Stop writer repair, not native completion.
	c.stopping = true
	c.fault = nil
	s.mu.Lock()
	err = c.publishLocked()
	s.mu.Unlock()
	if err != nil || r.records.current(ctx, true) != nil || r.healthCheck != c || !s.pending {
		t.Fatal("original partial ACK could not be repaired without losing fence", err)
	}
}

func TestMihomoActiveCheckingClosingFailureRetainsReader9(t *testing.T) {
	c, ctx := mihomoCheckingWriterModel(t)
	s := c.owner.scope
	s.mu.Lock()
	err := c.publishLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	cut := errors.New("model original closing cut")
	c.fault = func(step string) error {
		if step == "before-completion-current" {
			return cut
		}
		return nil
	}
	if err := c.complete(ctx); !errors.Is(err, cut) {
		t.Fatal(err)
	}
	c.fail()
	if !s.pending || c.owner.healthCheck != c {
		t.Fatal("closing failure dropped original owner")
	}
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, s.managerRoot); err != nil || version != 9 {
		t.Fatal("committed ACK hid original reader9 format", version, err)
	}
}
