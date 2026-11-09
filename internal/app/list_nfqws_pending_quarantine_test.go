package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestNFQWSQuarantineForeignFrameCannotSuppressJournalFence(t *testing.T) {
	for _, cut := range []string{"nil", "copied", "foreign-app", "consumed"} {
		t.Run(cut, func(t *testing.T) {
			a := &App{Dataplane: dataplane.New(t.TempDir())}
			if err := os.Mkdir(filepath.Join(a.Dataplane.StateRoot, "latest-execution.json"), 0700); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-journal", Digest: strings.Repeat("a", 64), Ready: true, Noop: true}
			calls := 0
			f := &managedNFQPendingFrame{original: ctx, execution: &managedNFQWSListExecution{}, closeOperation: func() { calls++ }, release: func() { calls++ }, take: func() { calls++ }}
			f.self = f
			switch cut {
			case "nil":
				f = nil
			case "copied":
				copy := *f
				f = &copy
			case "consumed":
				f.used = true
			}
			execution, err := a.applyDataplaneOriginal(ctx, plan, nil, f)
			if !errors.Is(err, dataplane.ErrExecutionJournal) || execution.State != "journal-failed" || !a.Operations.Snapshot().Fenced || calls != 0 {
				t.Fatal("unissued frame suppressed fence or released owner", execution, err, calls)
			}
		})
	}
}

func TestNFQWSQuarantinePartialSourceCloseNeverBecomesKnownTerminal(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[fail], func(t *testing.T) {
			calls := 0
			cut := errors.New("original physical source close failed")
			scope := &ListScopeBinding{closePhysical: func() error {
				calls++
				if fail {
					return cut
				}
				return nil
			}}
			scope.self = scope
			packet := &NFQWSPacketScopeBinding{}
			packet.self = packet
			e := &managedNFQWSListExecution{scope: scope, packetScope: packet}
			for range 2 {
				err := e.closeQuarantineSources()
				if errors.Is(err, cut) != fail || !e.pendingSourcesClosing || e.pendingSourcesClosed == fail || !scope.closed || !packet.closed || calls != 1 {
					t.Fatal("partial source close was forgotten or reopened", err, calls, e.pendingSourcesClosed)
				}
			}
		})
	}
}
