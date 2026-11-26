package physicalscope

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Models only an outer App error chain. No observation/fence or positive
// physical result is created, replaced, retried or waived by diagnostics.
func TestPhysicalDiagnosticStagesExtractsClosedLabelsThroughOuterCause(t *testing.T) {
	private := &privateDiagnosticCause{} // Error panics if caller input is formatted
	physical := boundary("verify.capture", boundary("capture.initial.current", at("fence.notifications", context.DeadlineExceeded)))
	outer := errors.Join(private, physical, context.Canceled)
	want := []string{"verify.capture", "capture.initial.current", "fence.notifications", "context.deadline", "context.canceled"}
	if got := DiagnosticStages(outer); !reflect.DeepEqual(got, want) {
		t.Fatalf("actual private labels missing: %q", got)
	}
	if !errors.Is(outer, private) || !errors.Is(outer, context.DeadlineExceeded) || !errors.Is(outer, context.Canceled) {
		t.Fatal("diagnostic extraction changed original causes")
	}
	copy := DiagnosticStages(outer)
	copy[0] = "caller-copy"
	if got := DiagnosticStages(outer); !reflect.DeepEqual(got, want) {
		t.Fatal("caller stage copy changed original error")
	}
	if len(DiagnosticStages(nil)) != 0 || len(DiagnosticStages(private)) != 0 || len(DiagnosticStages(errors.New("physical LAN: caller-forged-stage"))) != 0 {
		t.Fatal("foreign text supplied a private stage")
	}
}

func TestPhysicalDiagnosticStagesKeepsExistingTraversalBound(t *testing.T) {
	var deep error = at("snapshot.members", &privateDiagnosticCause{})
	for range 100 {
		deep = boundary("verify.capture", deep)
	}
	if stages := DiagnosticStages(deep); len(stages) > 16 {
		t.Fatal("depth limit widened", len(stages))
	}
	wide := make([]error, 100)
	for i := range wide {
		wide[i] = at("snapshot.device-binding", &privateDiagnosticCause{})
	}
	if stages := DiagnosticStages(errors.Join(wide...)); len(stages) > 64 {
		t.Fatal("node limit widened", len(stages))
	}
}

func TestPhysicalDiagnosticStagesKeepsPrimaryNotificationThroughJoinedCleanup(t *testing.T) {
	private := &privateDiagnosticCause{}
	var forward error = at("notifications.neighbor.delete", private)
	for _, stage := range []string{"fence.notifications", "capture.initial.fence.before", "capture.initial.current", "verify.capture"} {
		forward = boundary(stage, forward)
	}
	// App/COMMON wrappers are opaque to this package. They used to exhaust
	// the depth limit before the original notification, while a shallower
	// joined cleanup error misleadingly remained visible.
	for range 20 {
		forward = fmt.Errorf("opaque outer boundary: %w", forward)
	}
	joined := errors.Join(forward, at("retained.review.unavailable", nil))
	want := []string{"verify.capture", "capture.initial.current", "capture.initial.fence.before", "fence.notifications", "notifications.neighbor.delete", "retained.review.unavailable"}
	if got := DiagnosticStages(joined); !reflect.DeepEqual(got, want) {
		t.Fatalf("original notification hidden by outer wrappers: %q", got)
	}
	if !errors.Is(joined, private) || !errors.Is(joined, ErrUnknown) {
		t.Fatal("diagnostic extraction changed original causes")
	}
}

type cyclicDiagnosticWrapper struct{}

func (e *cyclicDiagnosticWrapper) Error() string { panic("formatted opaque cycle") }
func (e *cyclicDiagnosticWrapper) Unwrap() error { return e }

func TestPhysicalDiagnosticStagesBoundsOpaqueTraversal(t *testing.T) {
	if got := DiagnosticStages(&cyclicDiagnosticWrapper{}); len(got) != 0 {
		t.Fatal("opaque cycle supplied a private label")
	}
	var wrapped error = at("notifications.neighbor.delete", nil)
	for range 64 {
		wrapped = fmt.Errorf("opaque outer boundary: %w", wrapped)
	}
	if got := DiagnosticStages(wrapped); len(got) != 0 {
		t.Fatal("node limit widened", got)
	}
}
