package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type nfqws2CandidateDisruptor struct {
	*fakeAdapter
	activate func()
	health   func()
}

func (a *nfqws2CandidateDisruptor) Activate(context.Context, Plan, string) error {
	a.activate()
	return a.call("activate")
}
func (a *nfqws2CandidateDisruptor) Health(context.Context, Plan, string) error {
	if a.health != nil {
		a.health()
	}
	return a.call("health")
}
func (a *nfqws2CandidateDisruptor) VerifyRollback(context.Context, Plan, string) (bool, error) {
	return a.rollback, nil
}

func TestNFQWS2CandidateSettlementManagerAfterAllActivate(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, mode := range []string{"full", "loss", "partial", "queue-changed", "run-changed", "cancel-after-activation"} {
		t.Run(mode, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			plan := h.plan
			plan.PlanID = "dp-cccccccccccccccc"
			plan.Digest = strings.Repeat("c", 64)
			plan.Revision++
			plan.Adapters = []string{"nfqws2", "sing-box"}
			plan.Routes = append(slices.Clone(plan.Routes), Route{ServiceID: "telegram", Resolved: "sing-box", CIDRs: []string{"149.154.160.0/20"}})
			ctx, cancel := context.WithCancel(firstStartContext(t))
			defer cancel()
			var originalRoot string
			activated := false
			other := &nfqws2CandidateDisruptor{fakeAdapter: &fakeAdapter{id: "sing-box"}}
			other.activate = func() {
				activated = true
				originalRoot = h.a.firstStartReviewRoot
				if h.a.firstStartReview == nil || originalRoot != filepath.Join(h.m.StateRoot, "transactions", plan.PlanID, "nfqws2") {
					t.Fatal("candidate native review not retained")
				}
				if mode != "full" {
					h.lose(t, 4)
				}
				switch mode {
				case "partial":
					if err := h.kernel.apply(4, []string{"-t", "mangle", "-N", "nfqws_post"}); err != nil {
						t.Fatal(err)
					}
				case "queue-changed":
					h.queueOwner++
				case "run-changed":
					writeStockText(t, h.a.ConfigPath+".run", readText(t, h.a.ConfigPath+".run")+"FOREIGN_SCOPE=1\n")
				case "cancel-after-activation":
					cancel()
				}
			}
			other.health = func() {
				if !activated || h.a.firstStartReview == nil || h.a.firstStartReviewRoot != originalRoot {
					t.Fatal("settlement lost borrowed review ownership")
				}
				if !nfqws2HookSameRows(h.kernel.rows(), h.fullKernel(t).rows()) {
					t.Fatal("Health saw unconfirmed graph")
				}
			}
			if err := h.m.Register(other); err != nil {
				t.Fatal(err)
			}
			result, err := h.m.Apply(ctx, plan, nil)
			good := mode == "full" || mode == "loss"
			if good && (err != nil || result.State != "committed") {
				t.Fatalf("candidate did not settle: state=%s err=%v", result.State, err)
			}
			if !good && err == nil {
				t.Fatal("unsafe settlement accepted")
			}
			settleIndex, lastActivate, firstHealth := -1, -1, -1
			for i, step := range result.Steps {
				if step.Phase == "activate" {
					lastActivate = i
				}
				if step.Phase == "settle-hooks" {
					settleIndex = i
				}
				if step.Phase == "health" && firstHealth < 0 {
					firstHealth = i
				}
			}
			if good && (settleIndex <= lastActivate || firstHealth <= settleIndex) {
				t.Fatal("settlement not between all Activate and Health")
			}
			if !good && slices.Contains(other.calls, "health") {
				t.Fatal("Health ran after settlement refusal")
			}
			journal := filepath.Join(h.m.StateRoot, "transactions", plan.PlanID, "nfqws2", nfqws2CandidateHooksJournal)
			raw, readErr := os.ReadFile(journal)
			if mode == "full" {
				if !errors.Is(readErr, os.ErrNotExist) || len(h.writes) != 0 {
					t.Fatal("FULL was not a write-free no-op")
				}
			}
			if mode == "loss" {
				var doc nfqws2CandidateHookRecord
				if readErr != nil || json.Unmarshal(raw, &doc) != nil || doc.State != "settled" || len(doc.Effects) != 12 {
					t.Fatal("exact candidate effect journal missing")
				}
				for _, effect := range doc.Effects {
					if effect.State != "acknowledged" {
						t.Fatal("unacknowledged success")
					}
				}
			}
			if mode == "partial" || mode == "queue-changed" || mode == "run-changed" {
				if len(h.writes) != 0 {
					t.Fatal("refusal issued forward hook commands")
				}
			}
			h.assertWriterReleased(t)
		})
	}
}
