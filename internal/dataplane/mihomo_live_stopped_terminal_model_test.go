package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Documentary terminal/publication only: real original journal FDs and Gate,
// but retirement is explicitly modeled. This issues no public native proof.
func TestMihomoLiveStoppedPlanUsesOriginalCommittedDocument(t *testing.T) {
	t.Run("minimal-definition", func(t *testing.T) {
		testMihomoStoppedOriginalCommittedDocument(t)
	})
	t.Run("actual-compiler", func(t *testing.T) {
		original, _ := mihomoStoppedCompilerWireFixture(t)
		testMihomoStoppedOriginalCommittedDocument(t, original)
	})
}

func testMihomoStoppedOriginalCommittedDocument(t *testing.T, originalPlan ...Plan) {
	m, _, r, e := mihomoLiveRecordModel(t, originalPlan...)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r.control, err = gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.control.Close()
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	r.scope.retained = true
	r.retired = true
	terminal := &MihomoLiveTerminal{owner: r}
	terminal.self = terminal
	r.terminal = terminal
	e.State = "rolled-back"
	e.Resources[0].State, e.Resources[0].Phase = "removed", "removed"
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.publishRecords(raw); err != nil {
		t.Fatal(err)
	}
	before := r.definition.Clone().Plan
	before.State, before.Note = "committed", "actual Manager result bookkeeping"
	if err := m.Record(before); err != nil {
		t.Fatal(err)
	}
	actual, found, err := m.Committed()
	if err != nil || !found {
		t.Fatal(err)
	}
	if !mihomoStoppedOriginalPlanMatches(r.definition.Plan, actual) {
		t.Fatal("current result does not match frozen intent before Stop publication")
	}
	result, err := m.publishRetiredMihomoPlan(held, terminal, cleanup, before.Revision+1)
	if err != nil {
		t.Fatal("original stopped-plan publication", err)
	}
	if result.State != "committed" || !result.Noop || len(result.Routes) != 0 || result.Revision != before.Revision+1 {
		t.Fatal("invalid stopped documentary plan")
	}
	if terminal.stopped == nil || !terminal.stopped.files[0].ack || !terminal.stopped.files[1].ack {
		t.Fatal("missing original dual ACK")
	}
	t.Cleanup(func() {
		for _, held := range terminal.stopped.files {
			if held.file != nil {
				_ = held.file.Close()
			}
		}
		_ = terminal.stopped.root.Close()
	})
	if _, err := m.publishRetiredMihomoPlan(held, terminal, cleanup, before.Revision+1); err != nil {
		t.Fatal("same original acknowledged publication retry", err)
	}
	for cut := range terminal.stopped.files {
		file := &terminal.stopped.files[cut]
		original, err := file.file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		// Lost acknowledgment AFTER the real publication+directory sync.
		// This changes no document and cannot create a replacement writer.
		file.ack = false
		if _, err := m.publishRetiredMihomoPlan(held, terminal, cleanup, before.Revision+1); err != nil {
			t.Fatal("lost original ACK retry", cut, err)
		}
		after, err := file.file.Stat()
		if err != nil || !file.ack || !os.SameFile(original, after) {
			t.Fatal("retry replaced original writer", cut, err)
		}
	}
	if err := terminal.stopped.root.WriteAtomic(mihomoStoppedPlanNames[1], terminal.stopped.data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.publishRetiredMihomoPlan(held, terminal, cleanup, before.Revision+1); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("equal-byte foreign inode replaced original publication", err)
	}
}
