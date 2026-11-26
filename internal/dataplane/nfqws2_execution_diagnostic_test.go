package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNFQWSExecutionDiagnosticsPreserveOriginalPreflightClassification(t *testing.T) {
	secret := errors.New("private-command-path-and-credentials")
	original := preflightRefusalError{errors.Join(ErrNFQWSScopedOwner, context.DeadlineExceeded, secret)}
	wrapped := nfqwsExecutionFailure("activate.issue", nfqwsExecutionFailure("activation.scope", original))
	var refusal preflightRefusalError
	if !errors.As(wrapped, &refusal) || !errors.Is(wrapped, secret) || !errors.Is(wrapped, context.DeadlineExceeded) || !errors.Is(wrapped, ErrNFQWSScopedOwner) || errors.Is(wrapped, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("diagnostic changed original admission/issuance classification")
	}
	if strings.Contains(wrapped.Error(), secret.Error()) {
		t.Fatal("private payload exposed")
	}
	cleanup := nfqws2ActiveFailure("active Stop", secret)
	if got := NFQWSExecutionFailureStages(errors.Join(wrapped, cleanup)); !reflect.DeepEqual(got, []string{"activate.issue", "activation.scope", "active Stop"}) {
		t.Fatalf("joined stages %q", got)
	}
	if nfqwsExecutionFailure("activate.issue", nil) != nil {
		t.Fatal("success changed")
	}
}

func TestNFQWSExecutionDiagnosticsOnlyClosedBoundedStages(t *testing.T) {
	secret := errors.New("private-command-path-and-credentials")
	if got := NFQWSExecutionFailureStages(errors.Join(nfqwsExecutionFailure(secret.Error(), secret), nfqws2ActiveFailure(secret.Error(), secret))); len(got) != 0 {
		t.Fatal("unknown labels exposed")
	}
	var err error = secret
	for i := 0; i < 256; i++ {
		err = nfqwsExecutionFailure("activate.issue", err)
	}
	if got := NFQWSExecutionFailureStages(err); len(got) != 24 {
		t.Fatal("unbounded diagnostic", len(got))
	}
}

func TestNFQWSExecutionCommonDiagnosticsRetainUnknownAndOriginalCause(t *testing.T) {
	secret := errors.New("private-common-receipt-path")
	for _, stage := range []string{"retire.common-binding", "retire.cleanup-owner", "retire.policy-remove", "retire.verify-inactive", "retire.settle-removed", "retire.closing-owner", "remove.original-recovery", "remove.ordinary", "remove.settled-recovery", "remove.document-current", "remove.prepare", "remove.process-inactive", "remove.initial-readback", "remove.known-effects", "remove.receipt-effects", "remove.verify-inactive"} {
		original := errors.Join(ErrPolicyAdditionUnknown, context.DeadlineExceeded, secret)
		wrapped := nfqws2ActiveFailure("retire prepared", nfqwsExecutionFailure("retire.common", nfqwsExecutionFailure(stage, original)))
		if !errors.Is(wrapped, ErrPolicyAdditionUnknown) || !errors.Is(wrapped, context.DeadlineExceeded) || !errors.Is(wrapped, secret) {
			t.Fatal("original cleanup classification lost", stage)
		}
		if strings.Contains(wrapped.Error(), secret.Error()) {
			t.Fatal("private cleanup details exposed", stage)
		}
		if got := NFQWSExecutionFailureStages(wrapped); !reflect.DeepEqual(got, []string{"retire prepared", "retire.common", stage}) {
			t.Fatal("missing fixed common subphase", got)
		}
	}
}

func TestNFQWSExecutionRemoveReportsOriginalFailingBoundary(t *testing.T) {
	for _, stage := range []string{"remove.prepare", "remove.process-inactive", "remove.initial-readback", "remove.receipt-effects"} {
		t.Run(stage, func(t *testing.T) {
			b, model, root := nfqwsScopedRemoveFixture(t)
			cause := errors.New("private-remove-source-detail")
			switch stage {
			case "remove.prepare":
				b.Runner = nil
				cause = ErrNFQWSScopedOwner
			case "remove.process-inactive":
				b.ProcessInactive = func(context.Context, *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
					return NFQWSScopedProcessProof{}, cause
				}
			case "remove.initial-readback":
				b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error { return cause }
			case "remove.receipt-effects":
				b.CleanupGuard = func(context.Context, *NFQWSScopedPlan, PolicyEffect) error { return cause }
			}
			before := len(model.calls)
			err := b.Remove(context.Background(), model.p, root)
			if !errors.Is(err, cause) || !reflect.DeepEqual(NFQWSExecutionFailureStages(err), []string{stage}) || len(model.calls) != before {
				t.Fatal("failure cause, boundary, or no-effect behavior changed", stage, err)
			}
			if strings.Contains(err.Error(), "private-remove-source-detail") {
				t.Fatal("private cause exposed")
			}
		})
	}
}
