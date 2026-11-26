package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func admissionReconcilerFixture(t *testing.T) (*App, time.Time) {
	t.Helper()
	a := autonomyAPIFixture(t)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	for _, kind := range []string{"node-fallback", "service-checks"} {
		a.reconciler.doc.Operations = append(a.reconciler.doc.Operations, automationOperation{Kind: kind, State: "completed", Reason: "scheduled", ConfigFingerprint: automationConfigFingerprint(a.Store.Get()), NextRun: now.Add(time.Hour)})
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, now
}

func holdReconcilerWriter(t *testing.T, a *App) *restorejournal.FileTarget {
	t.Helper()
	f, err := restorejournal.OpenFileTarget(a.reconciler.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestReconcilerRetriesOnlyPrewriteAdmissionPreservingCompletedCheckpoint(t *testing.T) {
	a, now := admissionReconcilerFixture(t)
	w := holdReconcilerWriter(t, a)
	before := append([]byte(nil), a.reconciler.image.Data...)
	// A completed operation can already have real side effects. Preserve its
	// completion and consumed budget; recovery must not reload/replay old work.
	a.reconciler.doc.Sequence++
	a.reconciler.doc.Fallback["telegram"] = fallbackCheckpoint{Status: nodeAutofallbackService{ServiceID: "telegram"}, SwitchAttempts: []time.Time{now}}
	a.reconciler.doc.Operations[0].ID = a.reconciler.doc.Sequence
	expected, _ := json.Marshal(a.reconciler.doc)
	if err := a.persistReconcilerLocked(context.Background()); !restorejournal.RetryableFileAdmission(err) || !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("kernel admission failure lost its prewrite classification", err)
	}
	a.reconcileRound(context.Background(), now)
	onDisk, _ := os.ReadFile(a.reconciler.path)
	if !a.reconciler.blocked || !a.reconciler.retryAdmission || !bytes.Equal(before, onDisk) {
		t.Fatal("live competing writer admitted scheduler work")
	}
	_ = w.Close()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	a.reconcileRound(canceled, now)
	onDisk, _ = os.ReadFile(a.reconciler.path)
	if !a.reconciler.blocked || !a.reconciler.retryAdmission || !bytes.Equal(before, onDisk) {
		t.Fatal("canceled admission retry wrote metadata or cleared the fence")
	}
	a.reconcileRound(context.Background(), now)
	onDisk, _ = os.ReadFile(a.reconciler.path)
	if a.reconciler.blocked || a.reconciler.retryAdmission || a.reconciler.blockedCode != "" || !bytes.Equal(expected, onDisk) {
		t.Fatal("exact admission retry failed or reloaded completed checkpoint")
	}
	if got := a.reconciler.doc.Fallback["telegram"].SwitchAttempts; len(got) != 1 || !got[0].Equal(now) {
		t.Fatal("retry erased the switch budget")
	}
}

func TestReconcilerAdmissionRetryRefusesChangedJournalOrUnknownMarker(t *testing.T) {
	for _, drift := range []string{"journal", "marker"} {
		t.Run(drift, func(t *testing.T) {
			a, now := admissionReconcilerFixture(t)
			w := holdReconcilerWriter(t, a)
			a.reconciler.doc.Sequence++
			_ = a.persistReconcilerLocked(context.Background())
			_ = w.Close()
			path := a.reconciler.path
			foreign := []byte(`{"foreign":true}`)
			if drift == "marker" {
				key := sha256.Sum256([]byte(filepath.Base(path)))
				path = filepath.Join(filepath.Dir(path), ".state-"+hex.EncodeToString(key[:])+".lock")
				marker, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				foreign = bytes.Repeat([]byte("?"), len(marker))
			}
			if err := os.WriteFile(path, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			a.reconcileRound(context.Background(), now)
			got, _ := os.ReadFile(path)
			if !a.reconciler.blocked || a.reconciler.retryAdmission || !bytes.Equal(got, foreign) {
				t.Fatal("foreign journal or unknown marker was accepted/replaced")
			}
		})
	}
}

func TestReconcilerUnknownWriteOrLegacyRefusalNeverBecomesRetryable(t *testing.T) {
	for _, refusal := range []error{restorejournal.ErrRecovery, restorejournal.ErrBusy, restorejournal.ErrConflict, restorejournal.ErrInvalid, restorejournal.ErrUnavailable} {
		t.Run(refusal.Error(), func(t *testing.T) {
			a, now := admissionReconcilerFixture(t)
			before := append([]byte(nil), a.reconciler.image.Data...)
			a.blockReconcilerLocked(refusal)
			// A later prewrite refusal cannot downgrade a prior unknown outcome.
			w := holdReconcilerWriter(t, a)
			a.reconciler.doc.Sequence++
			_ = a.persistReconcilerLocked(context.Background())
			_ = w.Close()
			a.reconcileRound(context.Background(), now)
			got, _ := os.ReadFile(a.reconciler.path)
			if !a.reconciler.blocked || a.reconciler.retryAdmission || !bytes.Equal(got, before) {
				t.Fatal("legacy/unknown write fence was downgraded")
			}
		})
	}
}

func TestReconcilerStartupAdmissionFailureNeverRetriesEmptyRecoveryDocument(t *testing.T) {
	a, now := admissionReconcilerFixture(t)
	w := holdReconcilerWriter(t, a)
	before := append([]byte(nil), a.reconciler.image.Data...)
	b := &App{Store: a.Store}
	ctx, cancel := context.WithCancel(context.Background())
	b.StartServiceReconciler(ctx)
	cancel()
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := b.WaitServiceReconciler(joined); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	b.reconcileRound(context.Background(), now)
	got, _ := os.ReadFile(a.reconciler.path)
	if !b.reconciler.blocked || b.reconciler.retryAdmission || !bytes.Equal(got, before) {
		t.Fatal("failed startup retried an empty document over existing history")
	}
}

func TestAutonomyViewProjectsSchedulerFenceWithoutChangingPolicyOrRuntime(t *testing.T) {
	a, _ := admissionReconcilerFixture(t)
	if err := a.loadAutonomy(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := a.autonomyView(time.Now())
	a.blockReconcilerLocked(restorejournal.ErrBusy)
	view := a.autonomyView(time.Now())
	if view["blocked"] != true || view["blocked_code"] != "writer-busy" || !strings.Contains(view["maintenance_message"].(string), "планировщик") || !reflect.DeepEqual(view["policy"], before["policy"]) || !reflect.DeepEqual(view["runtime"], before["runtime"]) {
		t.Fatal("scheduler fence was hidden or changed runtime/policy")
	}
}
