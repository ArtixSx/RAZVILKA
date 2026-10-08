package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Actual Manager journal writers, held roots/inodes, and original sealed ACK
// protocol, with explicit native/queue models. These are not an App native run.
func TestRetainedNFQWSBothOriginalJournalBookendsAndColdACTIVERefusal(t *testing.T) {
	for _, change := range []string{"transaction-content", "latest-content", "transaction-replaced", "latest-replaced", "root-replaced"} {
		t.Run(change, func(t *testing.T) {
			if change == "root-replaced" && runtime.GOOS == "windows" {
				t.Skip("Windows denies replacing this held directory; exercise substitution on Linux")
			}
			f := nfqwsApplyTransferBoundFixture(t)
			s := f.r.scope
			if err := s.beginNFQWSTransfer(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.commitNFQWSTransfer(f.ctx); err != nil {
				t.Fatal(err)
			}
			s.execution.State = "committed"
			s.execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			s.execution.Resources[0].State, s.execution.Resources[0].Phase = "active", "active"
			if err := s.persist(); err != nil {
				t.Fatal(err)
			}
			if err := validateExecutionResources(*s.execution, true); err != nil {
				t.Fatal("valid documentary ACTIVE", err)
			}
			if err := s.manager.checkExecutionRecovery(); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("cold ACTIVE reconstructed owner", err)
			}
			root, anchor, err := openNetworkPolicyObservationRoot(s.managerRoot)
			if err != nil {
				t.Fatal(err)
			}
			o := &retainedNFQWSExecution{scope: s, root: root, anchor: anchor}
			o.self = o
			defer o.closeRecords()
			if err := o.captureRecords(); err != nil {
				t.Fatal(err)
			}
			if err := o.recordsCurrent(); err != nil {
				t.Fatal("original BOTH record bookends", err)
			}
			path := filepath.Join(s.root, "execution.json")
			if change == "latest-content" || change == "latest-replaced" {
				path = filepath.Join(s.managerRoot, "latest-execution.json")
			}
			switch change {
			case "root-replaced":
				if err := os.Rename(s.managerRoot, s.managerRoot+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(s.managerRoot, 0700); err != nil {
					t.Fatal(err)
				}
			case "transaction-replaced", "latest-replaced":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			default:
				s.execution.Error = "foreign write"
				if err := s.manager.writeExecution(s.root, *s.execution); err != nil {
					t.Fatal(err)
				}
			}
			if err := o.recordsCurrent(); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("changed or replaced original record accepted", err)
			}
		})
	}
}

func TestManagedNFQWSReadyPlanCannotFallBackToPackageOwner(t *testing.T) {
	f := nfqwsApplyTransferBoundFixture(t)
	m := f.r.scope.manager
	plan := cloneExecutionResourcePlan(f.r.scope.plan)
	plan.LAN = lanRuntimeFixture(t)
	plan.Routes[0].Sources = []string{"192.168.1.40/32"}
	for _, raw := range []any{nil, true, &nfqws2ActiveExecution{}} {
		ctx := f.ctx
		if raw != nil {
			ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, raw)
		}
		if err := m.checkManagedNFQWSApply(ctx, plan); !errors.Is(err, ErrNFQWSScopedOwner) {
			t.Fatal("ready DTO downgraded to global package", err)
		}
	}
}

func TestNFQWSResourceRejectsStatePhaseDowngrade(t *testing.T) {
	f := nfqwsApplyTransferBoundFixture(t)
	f.r.scope.execution.Resources[0].State = "active"
	if _, err := f.r.matching(f.r.binding); err == nil {
		t.Fatal("ACTIVE with capture-ready phase matched")
	}
	f.r.scope.execution.Resources[0].State = "prepared"
	f.r.scope.execution.Resources[0].Phase = "active"
	if _, err := f.r.matching(f.r.binding); err == nil {
		t.Fatal("prepared with ACTIVE phase matched")
	}
}
