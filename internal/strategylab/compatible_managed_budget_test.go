package strategylab

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Context arithmetic model only: this does not issue a runtime lease, control,
// receipt or native compatibility result. Actual owner checks must still refuse
// this deliberately incomplete invocation, as the last test verifies.
func compatibilityBudgetModel(t *testing.T) (context.Context, *SupervisedCompatibilityProvider, context.CancelFunc) {
	t.Helper()
	parent, cancel := context.WithTimeout(context.Background(), 36*time.Second)
	m := &Manager{}
	p := &SupervisedCompatibilityProvider{manager: m, managedControl: &operationgate.ControlEpochReview{}}
	p.self = p
	i := &managedCompatibilityInvocation{manager: m, provider: p}
	ctx := context.WithValue(parent, managedCompatibilityContextKey{}, i)
	i.forward = ctx
	p.managedInvocation = i
	return ctx, p, cancel
}

func compatibilityBudgetRemaining(t *testing.T, ctx context.Context, want time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining > want || remaining < want-time.Second {
		t.Fatalf("context budget = %v, deadline present %t; want at most %v with a fresh reserve", remaining, ok, want)
	}
}

func TestManagedCompatibilityBudgetKeepsSeparatePhaseAndForwardDeadlines(t *testing.T) {
	ctx, p, cancel := compatibilityBudgetModel(t)
	defer cancel()
	validation, finish := compatibilityValidatorContext(ctx, CompatibleValidator{Timeout: 8 * time.Second, Provider: p})
	defer finish()
	compatibilityBudgetRemaining(t, validation, 36*time.Second)
	first, endFirst := compatibilityPhaseContext(validation, p)
	compatibilityBudgetRemaining(t, first, 8*time.Second)
	endFirst()
	second, endSecond := compatibilityPhaseContext(validation, p)
	defer endSecond()
	compatibilityBudgetRemaining(t, second, 8*time.Second)
	if validation.Err() != nil {
		t.Fatal("ending the first child revoked the original forward operation")
	}
	// The original caller still bounds every later phase.
	cancel()
	if !errors.Is(validation.Err(), context.Canceled) || !errors.Is(second.Err(), context.Canceled) {
		t.Fatal("phase budgets detached caller cancellation")
	}
}

func TestManagedCompatibilityBudgetEachChildHasEightSecondMaximum(t *testing.T) {
	ctx, p, cancel := compatibilityBudgetModel(t)
	defer cancel()
	phase, finish := compatibilityPhaseContext(ctx, p)
	defer finish()
	compatibilityBudgetRemaining(t, phase, 8*time.Second)
}

func TestManagedCompatibilityBudgetPublicationUsesLiveForwardNotReapedChildDeadline(t *testing.T) {
	ctx, _, cancel := compatibilityBudgetModel(t)
	defer cancel()
	active := &compatibilityInvocation{Command: compatibilityCommand{Deadline: time.Now().Add(-time.Second)}}
	before := active.Command.Deadline
	publication, finish := compatibilityPublicationContext(ctx, active)
	defer finish()
	if publication.Err() != nil || !compatibilityPublicationTimeCurrent(publication, active) {
		t.Fatal("completed child execution deadline also expired acknowledged publication", publication.Err())
	}
	compatibilityBudgetRemaining(t, publication, 5*time.Second)
	if active.Command.Deadline != before {
		t.Fatal("publication renewed the original immutable child command")
	}
	cancel()
	if !errors.Is(publication.Err(), context.Canceled) || compatibilityPublicationTimeCurrent(publication, active) {
		t.Fatal("ACK/publication reserve authorized an expired original operation")
	}
}

func TestManagedCompatibilityBudgetDoesNotChangeLegacyDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 36*time.Second)
	defer cancel()
	validation, finish := compatibilityValidatorContext(parent, CompatibleValidator{Timeout: 8 * time.Second})
	defer finish()
	compatibilityBudgetRemaining(t, validation, 8*time.Second)
	phase, finishPhase := compatibilityPhaseContext(parent, &SupervisedCompatibilityProvider{})
	defer finishPhase()
	compatibilityBudgetRemaining(t, phase, ProbeTimeout)
	active := &compatibilityInvocation{Command: compatibilityCommand{Deadline: time.Now().Add(-time.Second)}}
	publication, finishPublication := compatibilityPublicationContext(parent, active)
	defer finishPublication()
	if !errors.Is(publication.Err(), context.DeadlineExceeded) || compatibilityPublicationTimeCurrent(publication, active) {
		t.Fatal("legacy expired child acquired a new publication reserve")
	}
}

func TestManagedCompatibilityBudgetCannotGrantMaterialAuthority(t *testing.T) {
	ctx, p, cancel := compatibilityBudgetModel(t)
	defer cancel()
	if p.managedMaterialCurrent(ctx) == nil {
		t.Fatal("bounded context model issued original runtime authority")
	}
	if err := p.manager.prepareCompatibilityPublicationLocked(ctx, Validation{}); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("context reserve bypassed actual publication admission", err)
	}
}

func TestManagedCompatibilityBudgetCannotRenewExpiredOrCopiedOriginal(t *testing.T) {
	for _, mode := range []string{"cancelled", "deadline", "copied"} {
		t.Run(mode, func(t *testing.T) {
			ctx, _, cancel := compatibilityBudgetModel(t)
			defer cancel()
			i := managedCompatibilityForward(ctx)
			if i == nil {
				t.Fatal("missing context model")
			}
			// A fresh caller cannot replace the original invocation deadline.
			fresh, endFresh := context.WithTimeout(context.Background(), time.Minute)
			defer endFresh()
			fresh = context.WithValue(fresh, managedCompatibilityContextKey{}, i)
			active := &compatibilityInvocation{Command: compatibilityCommand{Deadline: time.Now().Add(-time.Second)}}
			switch mode {
			case "cancelled":
				cancel()
			case "deadline":
				expired, endExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer endExpired()
				i.forward = context.WithValue(expired, managedCompatibilityContextKey{}, i)
			case "copied":
				copy := *i
				fresh = context.WithValue(fresh, managedCompatibilityContextKey{}, &copy)
			}
			if compatibilityPublicationTimeCurrent(fresh, active) {
				t.Fatal("fresh caller/copy renewed the original forward authority")
			}
		})
	}
}

func TestManagedCompatibilityBudgetKeepsEarlierOriginalDeadline(t *testing.T) {
	ctx, p, cancel := compatibilityBudgetModel(t)
	defer cancel()
	short, finish := context.WithTimeout(ctx, 50*time.Millisecond)
	defer finish()
	want, _ := short.Deadline()
	validation, endValidation := compatibilityValidatorContext(short, CompatibleValidator{Provider: p})
	defer endValidation()
	phase, endPhase := compatibilityPhaseContext(validation, p)
	defer endPhase()
	publication, endPublication := compatibilityPublicationContext(validation, &compatibilityInvocation{})
	defer endPublication()
	for _, bounded := range []context.Context{validation, phase, publication} {
		if actual, ok := bounded.Deadline(); !ok || actual != want {
			t.Fatal("managed phase extended an earlier original deadline", actual, want)
		}
	}
}
