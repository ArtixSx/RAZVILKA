package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestCanceledScheduleWriteDoesNotDisableFutureRounds(t *testing.T) {
	a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
	initReconcilerFixture(t, a, time.Now())
	before, err := os.ReadFile(a.reconciler.path)
	if err != nil {
		t.Fatal(err)
	}
	a.reconciler.doc.Sequence++
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.persistReconcilerLocked(ctx); !errors.Is(err, restorejournal.ErrAborted) || a.reconciler.blocked {
		t.Fatal("ordinary cancellation fenced scheduler", err, a.reconciler.blocked)
	}
	after, err := os.ReadFile(a.reconciler.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("canceled write changed journal", err)
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(a.reconciler.path)
	if bytes.Equal(before, after) {
		t.Fatal("later round was not saved")
	}
}

func TestScheduleWriterConflictStillFencesAndExplainsOnce(t *testing.T) {
	for _, mode := range []string{"busy", "changed"} {
		t.Run(mode, func(t *testing.T) {
			a, _, _, _, _ := nodeAutofallbackFixture(t, 1)
			initReconcilerFixture(t, a, time.Now())
			a.Audit = auditlog.New(filepath.Join(t.TempDir(), "events.jsonl"))
			want := "writer-busy"
			if mode == "busy" {
				writer, err := restorejournal.OpenFileTarget(a.reconciler.path)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
			} else {
				want = "journal-changed"
				if err := os.WriteFile(a.reconciler.path, []byte("private-sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if err := a.persistReconcilerLocked(context.Background()); err == nil {
					t.Fatal("conflict accepted")
				}
			}
			if !a.reconciler.blocked || a.reconciler.blockedCode != want {
				t.Fatal(a.reconcilerSnapshot())
			}
			snapshot := a.Audit.Cached(10)
			if len(snapshot.Events) != 1 || snapshot.Events[0].Path != "/runtime/scheduler/"+want {
				t.Fatal(snapshot)
			}
			encoded, _ := json.Marshal(a.reconcilerSnapshot())
			if strings.Contains(string(encoded), "private-sentinel") || strings.Contains(string(encoded), a.reconciler.path) {
				t.Fatal("private reason leaked")
			}
		})
	}
}
