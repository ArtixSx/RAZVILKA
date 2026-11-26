//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Actual authored FD/byte custody only: this model has no native baseline,
// control admission, or fleet grant and cannot invoke the public retirement.
func domainTCPKeeperFilesFixture(t *testing.T) (*domainTCPGlobalKeeper, context.Context) {
	t.Helper()
	old, ctx := domainTCPGlobalHistoryFixture(t)
	m := New(old.rootPath)
	plan := domainTCPProofPlanModel(t)
	e := &Execution{PlanID: "dp-check-" + strings.Repeat("e", 32), ResourcePlanID: plan.PlanID, Digest: plan.Digest, State: "temporary-complete"}
	path := filepath.Join(m.StateRoot, "transactions", e.PlanID)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	s := &executionResourceScope{manager: m, managerRoot: m.StateRoot, root: path, plan: plan, execution: e}
	var err error
	s.owned, s.anchor, err = openNetworkPolicyObservationRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.owned.Close() })
	s.ctx, s.cancel = context.WithCancel(ctx)
	t.Cleanup(s.cancel)
	s.open = true
	d, err := newXraySelectedTCPRecords(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	p := &domainTCPStandbyPool{manager: m, entries: []*domainTCPStandbyPoolEntry{{history: old}}}
	p.self = p
	m.domainPool = p
	c := &domainTCPGlobalSuccessor{pool: p, scope: s, records: d}
	c.self = c
	s.domainSuccessor = c
	p.successor = c
	r := &domainTCPInitialRetirement{cursor: c}
	r.self = r
	c.terminal = r
	image, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	k := &domainTCPGlobalKeeper{pool: p, cursor: c, records: d, image: image, digest: sha256.Sum256(image)}
	k.self = k
	r.keeper = k
	p.keeper = k
	for i := range 2 {
		if err := d.publishOriginalDurable(i, image, syncDataplaneJournalDirectory); err != nil {
			t.Fatal(err)
		}
	}
	return k, ctx
}

func TestDomainInitialRetirementClosesOnlyOriginalUnenteredScope(t *testing.T) {
	for _, change := range []string{"none", "action-entered", "issued", "canceled", "foreign-transaction", "closed-retry-foreign"} {
		t.Run(change, func(t *testing.T) {
			k, ctx := domainTCPKeeperFilesFixture(t)
			r, c := k.cursor.terminal, k.cursor
			r.published = true
			switch change {
			case "action-entered":
				c.actionStarted = true
			case "issued":
				c.scope.issued = map[string]*executionTransitResource{"original": {}}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "foreign-transaction":
				if err := k.records.transactionRoot.WriteAtomic("execution.json", k.image, 0600); err != nil {
					t.Fatal(err)
				}
			case "closed-retry-foreign":
				if err := r.closeScopeOwner(ctx); err != nil {
					t.Fatal(err)
				}
				if err := k.records.transactionRoot.WriteAtomic("execution.json", k.image, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := r.closeScopeOwner(ctx)
			if change != "none" {
				if err == nil {
					t.Fatal("entered/canceled/foreign scope accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !r.scopeClosed || c.scope.open || c.scope.ctx.Err() == nil {
				t.Fatal("actual scope Close ACK not retained")
			}
			if _, err := c.scope.owned.RootInfo(); err == nil {
				t.Fatal("scope root remains open")
			}
			if err := k.records.current(ctx, true); err != nil {
				t.Fatal("scope close lost original journal custody", err)
			}
			if err := r.closeScopeOwner(ctx); err != nil {
				t.Fatal("same close ACK retry failed", err)
			}
		})
	}
}

func TestDomainKeeperRetainsOnlyOriginalAuthoredFiles(t *testing.T) {
	for _, change := range []string{"none", "not-ready", "copied", "foreign-global", "foreign-transaction", "changed-scope"} {
		t.Run(change, func(t *testing.T) {
			k, ctx := domainTCPKeeperFilesFixture(t)
			k.ready.Store(true)
			if err := k.current(ctx); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "not-ready":
				k.ready.Store(false)
			case "copied":
				k.self = &domainTCPGlobalKeeper{}
			case "foreign-global":
				if err := k.records.root.WriteAtomic("latest-execution.json", k.image, 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-transaction":
				if err := k.records.transactionRoot.WriteAtomic("execution.json", k.image, 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-scope":
				k.cursor.scope.execution.State = "checking"
			}
			err := k.current(ctx)
			if change != "none" {
				if err == nil {
					t.Fatal("foreign or unfinished custody accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, err := borrowDomainTCPKeeperHistory(ctx, k)
			if err != nil {
				t.Fatal(err)
			}
			if b.file != k.records.files[1] || b.records != k.records || b.keeper != k {
				t.Fatal("borrow replaced original holder")
			}
			if err := b.currentHistorical(ctx); err == nil {
				t.Fatal("unrenamed global became historical")
			}
		})
	}
}
