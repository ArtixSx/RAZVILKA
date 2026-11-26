package systemprobe

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInterruptedEpochDumpDiscardsPartialResults(t *testing.T) {
	ctx := context.Background()
	calls := 0
	messages, err := retryEpochDump(ctx, func(received context.Context) ([]epochMessage, error) {
		if received != ctx {
			t.Fatal("retry replaced the observation context")
		}
		calls++
		if calls < 3 {
			return []epochMessage{{kind: 99}}, errEpochDumpInterrupted
		}
		return []epochMessage{{kind: 24}}, nil
	})
	if err != nil || calls != 3 || len(messages) != 1 || messages[0].kind != 24 {
		t.Fatalf("partial interrupted dump escaped: calls=%d messages=%v err=%v", calls, messages, err)
	}
}

func TestEpochDumpRetryRemainsBoundedAndFailClosed(t *testing.T) {
	for _, failure := range []error{errEpochDumpInterrupted, ErrNetworkUnavailable, errors.New("notification overflow")} {
		calls := 0
		messages, err := retryEpochDump(context.Background(), func(context.Context) ([]epochMessage, error) {
			calls++
			return []epochMessage{{kind: 24}}, failure
		})
		wantCalls := 1
		if failure == errEpochDumpInterrupted {
			wantCalls = 3
		}
		if !errors.Is(err, failure) || len(messages) != 0 || calls != wantCalls {
			t.Fatalf("failure did not stay closed: calls=%d messages=%v err=%v", calls, messages, err)
		}
	}
}

func TestEpochDumpCancellationDiscardsOtherwiseValidSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	dump := func(context.Context) ([]epochMessage, error) {
		calls++
		cancel()
		return []epochMessage{{kind: 24}}, nil
	}
	for i := 0; i < 2; i++ {
		messages, err := retryEpochDump(ctx, dump)
		if !errors.Is(err, context.Canceled) || messages != nil || calls != 1 {
			t.Fatalf("canceled snapshot was accepted: calls=%d messages=%v err=%v", calls, messages, err)
		}
	}
}

func TestEpochDiagnosticRetainsFailureAfterObserverRestarts(t *testing.T) {
	source := &fakeEpochSource{state: fakeEpochSnapshot()}
	d := detectorForTest(source)
	before, err := d.fresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source.err = errors.New("private interface and path")
	if _, err := d.fresh(context.Background()); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatal("failed snapshot retained authority")
	}
	failed := d.diagnostic()
	source.err = nil
	after, err := d.fresh(context.Background())
	if err != nil || before.ID == after.ID {
		t.Fatal("restarted observer reused proof")
	}
	restored := d.diagnostic()
	if restored.Reason != "observer-start" || restored.LastFailureReason != "observation-failed-snapshot" || restored.LastFailureAt == "" || restored.LastFailureAt != failed.LastFailureAt {
		t.Fatalf("restart erased failure diagnostics: %+v", restored)
	}
	raw, _ := json.Marshal(restored)
	if strings.Contains(string(raw), "private") {
		t.Fatal("diagnostic exposed source error contents")
	}
}
