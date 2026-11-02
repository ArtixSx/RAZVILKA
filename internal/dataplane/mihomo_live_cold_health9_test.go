package dataplane

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Codec/terminal derivation only. Complete actual offline absence and original
// writer admission remain mandatory at publication; this data test issues none.
func settledMihomoColdHealth9Fixture(t *testing.T) Execution {
	t.Helper()
	e := mihomoCheckingExecutionFixture(t)
	e.State, e.FinishedAt = "committed", e.StartedAt
	e.MihomoLiveHealthOperation.Phase = "settled"
	if err := validateExecutionResources(e, true); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMihomoLiveColdHealth9TerminalPreservesAnchorsAndRetiresPhase(t *testing.T) {
	before := settledMihomoColdHealth9Fixture(t)
	original := *before.MihomoLiveHealthOperation
	after, err := mihomoLiveRetirementTerminal(before, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	want := original
	want.Phase = "retired"
	if after.MihomoLiveHealthOperation == before.MihomoLiveHealthOperation || !reflect.DeepEqual(*after.MihomoLiveHealthOperation, want) || !reflect.DeepEqual(*before.MihomoLiveHealthOperation, original) || after.RollbackVerified {
		t.Fatal("reader9 anchors/input alias or unverified rollback changed")
	}
	if version, err := MihomoLiveOfflineRetirementReadVersion(after); err != nil || version != 9 {
		t.Fatal("retired metadata lost reader9", version, err)
	}
	legacy := before
	legacy.MihomoLiveHealthOperation = nil
	if version, err := MihomoLiveOfflineRetirementReadVersion(legacy); err != nil || version != 8 {
		t.Fatal("legacy minimum changed", version, err)
	}
	if _, err := mihomoLiveRetirementTerminal(after, after.FinishedAt); !errors.Is(err, ErrMihomoLiveRetirement) {
		t.Fatal("retired operation reused as fresh cleanup intent", err)
	}
}

func TestMihomoLiveColdHealth9RefusesUnsettledHeaders(t *testing.T) {
	for _, phase := range []string{"checking", "retiring", "unknown"} {
		t.Run(phase, func(t *testing.T) {
			e := settledMihomoColdHealth9Fixture(t)
			e.MihomoLiveHealthOperation.Phase = phase
			if phase == "checking" {
				e.State, e.FinishedAt = mihomoActiveCheckingState, ""
			}
			if phase == "retiring" {
				e.State, e.FinishedAt = "rolling-back", ""
			}
			raw, _ := json.Marshal(e)
			if _, _, err := decodeMihomoLiveRetirementIntent(raw); err == nil {
				t.Fatal("unsettled health was admitted for cold metadata")
			}
			if _, err := mihomoLiveRetirementTerminal(e, time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
				t.Fatal("unsettled health became retired")
			}
		})
	}
}
