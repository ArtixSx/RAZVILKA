package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// Real journal/archive parsers with modeled processes. This cannot establish
// the original executing App role and is not native retirement acceptance.
func TestPairedRetirementSourceRequiresCompletedLiveHandoff(t *testing.T) {
	f := pairedReaderSetup(t)
	f.accept(t)
	r, err := f.store.RetainedReceipt(f.ctx, f.review.ID)
	if err != nil {
		t.Fatal(err)
	}
	job, err := f.adapter.commandRoot(f.review.ID)
	if err != nil {
		t.Fatal(err)
	}
	command, err := readFileCommand(job, f.review.ID, "start-candidate-panel")
	job.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePairedRetirementSource(f.updater.record, f.review, r, command, command.Supervisor.PID); err != nil {
		t.Fatal("completed metadata was rejected", err)
	}
	for _, change := range []string{"requires-review", "installed", "rollback", "runtime-ready", "wrong-worker", "wrong-runtime-sha", "cancelled", "missing-pair", "changed-review", "offline"} {
		t.Run(change, func(t *testing.T) {
			record, review, receipt, process := f.updater.record, f.review, r, command
			worker := process.Supervisor.PID
			switch change {
			case "requires-review":
				record.Job.State = change
			case "installed":
				receipt.Phase = change
			case "rollback":
				receipt.Rollback = true
			case "runtime-ready":
				process.State = change
			case "wrong-worker":
				worker++
			case "wrong-runtime-sha":
				process.Runtime.ExecutableSHA256 = record.ExecutableHash
			case "cancelled":
				process.Cancelled = true
			case "missing-pair":
				receipt.Paired = nil
			case "changed-review":
				record.FileReviewSHA256 = digestBytes([]byte("different review"))
			case "offline":
				review.Bootstrap = &fileBootstrapBinding{Mode: "offline"}
			}
			if !errors.Is(validatePairedRetirementSource(record, review, receipt, process, worker), ErrPairedRetirementOwner) {
				t.Fatal("ineligible source acquired retirement")
			}
		})
	}
	if err := f.adapter.RetireCompletedPairedState(f.ctx, f.review.ID, command.Supervisor.PID, func(context.Context, string) error { t.Fatal("fixture reached original App owner"); return nil }); !errors.Is(err, ErrPairedRetirementOwner) {
		t.Fatal("model roots acquired the production consumer", err)
	}
}

func TestPairedRetirementReceiptAllowsOnlyExactArchivedTransition(t *testing.T) {
	f := pairedReaderSetup(t)
	f.accept(t)
	accepted, err := f.store.RetainedReceipt(f.ctx, f.review.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f.updater.record)
	helperSHA := digestBytes(data)
	if !samePairedRetirementReceipt(accepted, accepted, helperSHA) {
		t.Fatal("original accepted receipt changed")
	}
	if err := f.retire(t); err != nil {
		t.Fatal(err)
	}
	archived, err := f.store.RetainedReceipt(f.ctx, f.review.ID)
	if err != nil || !samePairedRetirementReceipt(accepted, archived, helperSHA) {
		t.Fatal("actual archive transition changed its source", err)
	}
	changed := archived
	retired := *changed.Retired
	changed.Retired = &retired
	retired.HelperSHA256 = digestBytes([]byte("changed helper"))
	if samePairedRetirementReceipt(accepted, changed, helperSHA) {
		t.Fatal("foreign helper retirement was adopted")
	}
	changed = archived
	changed.Commands = append(append([]string(nil), changed.Commands...), "unknown-command")
	if samePairedRetirementReceipt(accepted, changed, helperSHA) {
		t.Fatal("changed accepted receipt was adopted")
	}
}

func TestPairedRetirementOwnerCannotBeCopiedRenewedOrRunByTestExecutable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	called := false
	p := &completedPairedRetirement{original: ctx, adapter: &SelfUpdateFileAdapter{}, owner: func(context.Context, string) error { called = true; return nil }}
	p.self = p
	copy := *p
	renewed, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	for _, tc := range []struct {
		cap *completedPairedRetirement
		ctx context.Context
	}{{nil, ctx}, {&copy, ctx}, {p, renewed}} {
		if !errors.Is(tc.cap.current(tc.ctx, ""), ErrPairedRetirementOwner) || called {
			t.Fatal("unbound owner reached callbacks")
		}
	}
	if !errors.Is(pairedRetirementExecutingApp(ctx, fileProcess{PID: os.Getpid()}), ErrPairedRetirementOwner) {
		t.Fatal("test executable acquired the actual installed App role")
	}
}
