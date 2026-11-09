//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"testing"
)

type sameBootPrivateFailure struct{}

func (*sameBootPrivateFailure) Error() string { panic("private error text must not be inspected") }
func (*sameBootPrivateFailure) Unwrap() error { panic("private error tree must not be inspected") }

func TestMihomoSameBootNativeFailureBoundedAndPrivate(t *testing.T) {
	original := &sameBootPrivateFailure{}
	stages := []string{"owner", "inputs-opening", "plan-inputs", "policy-close", "static-current", "static-close", "read-opening", "control-opening", "processes", "inputs-closing", "read-closing", "control-closing"}
	var late context.Context
	rows, err := WithMihomoSameBootNativeMeasurements(t.Context(), func(ctx context.Context) error {
		late = ctx
		for _, stage := range stages {
			if got := mihomoSameBootNativeFailure(ctx, stage, original); got != original {
				t.Fatal("original error identity changed")
			}
			if got := mihomoSameBootNativeFailure(ctx, stage, nil); got != nil {
				t.Fatal("success changed")
			}
		}
		if got := mihomoSameBootNativeFailure(ctx, "private-path-token-not-a-stage", original); got != original {
			t.Fatal("unknown stage changed refusal")
		}
		return original
	})
	if err != original || len(rows) != len(stages) {
		t.Fatal("bounded refusal rows or original return changed")
	}
	allowed := map[string]bool{}
	for _, stage := range stages {
		allowed["failure-"+stage] = true
	}
	for _, row := range rows {
		if !allowed[row.Phase] || row.Calls != 1 || row.Nanoseconds != 0 {
			t.Fatal("invalid diagnostic row")
		}
	}
	marker, _ := late.Value(mihomoSameBootMeasurementsKey{}).(*mihomoSameBootMeasurements)
	if got := mihomoSameBootNativeFailure(late, "owner", original); got != original {
		t.Fatal("expired diagnostic changed refusal")
	}
	if marker.rows["failure-owner"].Calls != 1 {
		t.Fatal("expired diagnostic recorded another row")
	}
	for _, ctx := range []context.Context{nil, t.Context(), context.WithValue(t.Context(), mihomoSameBootMeasurementsKey{}, "foreign")} {
		if got := mihomoSameBootNativeFailure(ctx, "owner", original); got != original {
			t.Fatal("missing/foreign diagnostic changed error")
		}
	}
}

func TestMihomoSameBootNativeProcFailurePrivateStage(t *testing.T) {
	cause := &sameBootPrivateFailure{}
	original := &scopedDNSInactiveProcFailure{stage: "proc.argv-recheck", cause: cause}
	var typedNil *scopedDNSInactiveProcFailure
	rows, err := WithMihomoSameBootNativeMeasurements(t.Context(), func(ctx context.Context) error {
		if got := mihomoSameBootNativeProcFailure(ctx, original); got != original {
			t.Fatal("original wrapper changed")
		}
		if got := mihomoSameBootNativeProcFailure(ctx, cause); got != cause {
			t.Fatal("foreign error changed")
		}
		if got := mihomoSameBootNativeProcFailure(ctx, typedNil); got != typedNil {
			t.Fatal("typed nil changed")
		}
		private := &scopedDNSInactiveProcFailure{stage: "private/path/token", cause: cause}
		if got := mihomoSameBootNativeProcFailure(ctx, private); got != private {
			t.Fatal("unknown original changed")
		}
		if got := mihomoSameBootNativeProcFailure(ctx, nil); got != nil {
			t.Fatal("success changed")
		}
		return original
	})
	if err != original || len(rows) != 2 {
		t.Fatal("unbounded stage or changed error")
	}
	for _, row := range rows {
		switch row.Phase {
		case "failure-process-inventory-proc.argv-recheck":
			if row.Calls != 1 {
				t.Fatal("known stage count")
			}
		case "failure-process-inventory-unknown":
			if row.Calls != 2 {
				t.Fatal("unknown count")
			}
		default:
			t.Fatal("private stage exposed")
		}
		if row.Nanoseconds != 0 {
			t.Fatal("unexpected timing")
		}
	}
}
