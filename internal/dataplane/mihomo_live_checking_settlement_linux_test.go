//go:build linux

package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Models ONLY the already-issued readback callback's one-shot ACK. Actual
// owned journal FDs/Gate are used, but no kernel unused/removed proof is minted.
func mihomoCheckingSettlementModel(t *testing.T) (*mihomoLiveHealthCheck, *executionTransitResource, context.Context) {
	t.Helper()
	c, forward := mihomoCheckingWriterModel(t)
	r, s := c.owner, c.owner.scope
	ctx, end, err := r.operation(forward, c.cleanup, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(end)
	spec := nodeTransitFixtureSpec()
	d := r.definition
	spec.Engine, spec.PlanID, spec.PlanDigest = "mihomo", s.execution.PlanID, s.execution.Digest
	spec.BootID, spec.NetworkProfile, spec.RuntimeID = d.NetworkIdentity.BootID, d.NetworkProfile, d.Profile.ConfigSHA256
	spec.Interface, spec.Table, spec.Priority = d.Policy.Interface, d.Policy.Table, 80
	compiled, err := CompileNodeTransit(spec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	id := "nt-" + strings.Repeat("c", 32)
	relative := filepath.Join("execution-resources", id)
	if err := s.owned.MkdirAll(relative, 0700); err != nil {
		t.Fatal(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil {
		t.Fatal(err)
	}
	resource := &executionTransitResource{spec: spec, root: filepath.Join(s.root, relative), relative: relative, anchor: anchor, digest: compiled.Generation, effects: digest}
	s.issued[id] = resource
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: id, Kind: "node-transit", State: "prepared", Generation: compiled.Generation, EffectsDigest: digest, NodeTransit: &spec})
	s.mu.Lock()
	err = c.publishLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return c, resource, ctx
}

func TestMihomoActiveCheckingUnusedSettlementResumesOnlyOriginalACK(t *testing.T) {
	c, resource, ctx := mihomoCheckingSettlementModel(t)
	s := c.owner.scope
	var modes []networkPolicyTransitReadbackMode
	resource.readback = func(_ context.Context, _ NodeTransitSpec, _, _ string, mode networkPolicyTransitReadbackMode) error {
		modes = append(modes, mode)
		return nil
	}
	cut := errors.New("model settlement ACK cut")
	c.fault = func(step string) error {
		if step == "before-latest" {
			return cut
		}
		return nil
	}
	settle := func(r *executionTransitResource) error {
		return s.settleTransit(ctx, r, r.spec, r.root, r.digest, networkPolicyTransitUnused)
	}
	if err := settle(resource); !errors.Is(err, cut) {
		t.Fatal(err)
	}
	if resource.settlementReadback != networkPolicyTransitUnused || resource.unusedSettled || s.failure != nil {
		t.Fatal("lost original readback/pending publication distinction")
	}
	c.fault = nil
	copyResource := *resource
	if err := settle(&copyResource); err == nil {
		t.Fatal("copied ACK became original issuer")
	}
	if err := settle(resource); err != nil {
		t.Fatal(err)
	}
	if !resource.unusedSettled || len(modes) != 2 || modes[0] != networkPolicyTransitUnused || modes[1] != networkPolicyTransitUnusedCurrent {
		t.Fatal("consumed proof replayed or fresh comparison omitted", modes)
	}
	if err := c.owner.records.current(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func TestMihomoActiveCheckingUnusedReadbackClosingCancellationKeepsACK(t *testing.T) {
	c, resource, ctx := mihomoCheckingSettlementModel(t)
	s := c.owner.scope
	canceled, cancel := context.WithCancel(ctx)
	resource.readback = func(_ context.Context, _ NodeTransitSpec, _, _ string, mode networkPolicyTransitReadbackMode) error {
		cancel()
		return nil
	}
	if err := s.settleTransit(canceled, resource, resource.spec, resource.root, resource.digest, networkPolicyTransitUnused); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if resource.settlementReadback != networkPolicyTransitUnused || resource.unusedSettled {
		t.Fatal("closing cancellation fabricated settlement or discarded consumed ACK")
	}
	var mode networkPolicyTransitReadbackMode
	resource.readback = func(_ context.Context, _ NodeTransitSpec, _, _ string, got networkPolicyTransitReadbackMode) error {
		mode = got
		return nil
	}
	if err := s.settleTransit(ctx, resource, resource.spec, resource.root, resource.digest, networkPolicyTransitUnused); err != nil {
		t.Fatal(err)
	}
	if mode != networkPolicyTransitUnusedCurrent || !resource.unusedSettled {
		t.Fatal("retry did not require fresh read-only original comparison", mode)
	}
}
