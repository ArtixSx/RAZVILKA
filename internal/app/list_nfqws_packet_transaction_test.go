package app

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Protocol model only: actual App/Store/Manager/control/gate/journal, modeled
// adapters + physical reads. This cannot test source/material production or
// grant native NFQ permission; the generic plan remains explicitly blocked.
func TestNFQWSPacketAppManagerProtocolModelCASAndRollback(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	for _, cut := range []string{"commit", "health", "CAS", "after-CAS-physical"} {
		t.Run(cut, func(t *testing.T) {
			a, b, m := nfqwsPacketFixture(t)
			a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
			a.DataplaneHost = func() dataplane.HostState {
				return dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true}
			}
			a.Dataplane.FreshProfile = func(context.Context) (string, error) { return b.snapshot.NetworkID, nil }
			gate := &defaultRouteTransactionAdapter{id: dataplane.NetworkPolicyAdapterID, app: a, verified: true}
			adapter := &defaultRouteTransactionAdapter{id: "nfqws2", app: a, verified: true}
			if err := a.Dataplane.Register(gate); err != nil {
				t.Fatal(err)
			}
			if err := a.Dataplane.Register(adapter); err != nil {
				t.Fatal(err)
			}
			listScopeOperation(t, a, func(c context.Context) {
				compiled := nfqwsPacketCompilation(t, c, a, b)
				if err := b.BindCompilation(c, compiled); err != nil {
					t.Fatal(err)
				}
				input := (&DefaultRouteExecutor{app: a}).input(compiled, a.Store.Get())
				plan, err := dataplane.BuildAt(input, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if plan.Ready {
					t.Fatal("generic DTO unexpectedly granted native scoped NFQ")
				}
				// Explicit test-only protocol envelope consumed only by test doubles.
				// Actual NFQWS2Adapter would reject without the original BindExecution.
				plan.Ready, plan.Blockers = true, nil
				before := a.Store.Get()
				commits := 0
				cleanup, err := a.Operations.ReviewExclusiveCleanup(c)
				if err != nil {
					t.Fatal(err)
				}
				if cut == "health" {
					adapter.healthErr = errors.New("modeled health failure")
				}
				c = dataplane.WithReviewGuard(c, func(current context.Context) error { return b.ScopeCheck(current, compiled.LAN()) })
				execution, applyErr := a.applyDataplane(c, plan, func() (func() error, error) {
					commits++
					if cut == "CAS" {
						return nil, errors.New("modeled CAS refusal")
					}
					started := time.Now()
					undo, e := a.Store.CommitNetworkPolicyWithRollback(before, compiled.Policy(), before.Services)
					finished := time.Now()
					if e != nil {
						return undo, e
					}
					if cut == "after-CAS-physical" {
						m.physicalErr = errors.New("modeled Home drift after CAS")
					}
					if e = b.AcceptCommitted(c, a.Store.Get(), started, finished); e != nil {
						return undo, e
					}
					return undo, b.ScopeCheck(c, compiled.LAN())
				})
				if cut == "commit" {
					if applyErr != nil || execution.State != "committed" || !adapter.live || !gate.live {
						t.Fatal("model commit failed", execution, applyErr)
					}
					if err = b.ScopeCheck(c, compiled.LAN()); err != nil {
						t.Fatal("original scope failed after real Manager CAS", err)
					}
					if _, err = a.Dataplane.Deactivate(c); err != nil {
						t.Fatal("modeled consumer Stop", err)
					}
					if adapter.live || gate.live {
						t.Fatal("model Stop left participants live")
					}
					if err = cleanup.WithCurrent(c, func() error { return b.cleanupScopeCheck(c, compiled.LAN()) }); err != nil {
						t.Fatal(err)
					}
				} else {
					if applyErr == nil || execution.State != "rolled-back" || adapter.live || gate.live {
						t.Fatal("failure did not roll back model participants", execution, applyErr)
					}
					if !reflect.DeepEqual(a.Store.Get(), before) {
						t.Fatal("failed transaction did not restore exact Store")
					}
					if cut == "after-CAS-physical" {
						m.physicalErr = nil
					}
					// Forward owner may be poisoned by a failed closing check/CAS, while
					// unchanged original physics still supports receipt cleanup.
					if err = cleanup.WithCurrent(c, func() error { return b.cleanupScopeCheck(c, compiled.LAN()) }); err != nil {
						t.Fatal("rollback lost retained cleanup", err)
					}
				}
				if cut == "health" && commits != 0 || cut != "health" && commits != 1 {
					t.Fatal("wrong CAS ordering", commits)
				}
				if !strings.Contains(strings.Join(adapter.steps, ","), "activate") {
					t.Fatal("model never reached effects")
				}
			})
		})
	}
}
