package operationgate

import (
	"context"
	"sync/atomic"
	"time"
)

// Progress describes the work of one admitted holder, never its result or
// permission to change a route. A deadline is the original admitted context's
// bound: reaching it does not prove that cancellation or cleanup has finished.
// Every Snapshot returns a detached value, including its optional fields.
type Progress struct {
	ID               uint64     `json:"id"`
	Kind             string     `json:"kind"`
	Phase            string     `json:"phase"`
	ServiceID        string     `json:"service_id,omitempty"`
	StartedAt        time.Time  `json:"started_at"`
	PhaseStartedAt   time.Time  `json:"phase_started_at"`
	DeadlineAt       *time.Time `json:"deadline_at,omitempty"`
	ElapsedSeconds   int64      `json:"elapsed_seconds"`
	PhaseSeconds     int64      `json:"phase_seconds"`
	RemainingSeconds *int64     `json:"remaining_seconds,omitempty"`
	DeadlineExceeded bool       `json:"deadline_exceeded"`
}

type progressContextKey struct{}

type progressStep struct {
	phase     string
	serviceID string
	since     time.Time
}

type progressTracker struct {
	kind    string
	claimed atomic.Bool
	step    atomic.Pointer[progressStep]
}

type admittedProgress struct {
	tracker     *progressTracker
	deadline    time.Time
	hasDeadline bool
}

// WithProgress prepares allowlisted presentation metadata for the first
// successful admission of ctx. Updates only replace an immutable memory value;
// they neither enter the Gate nor inspect Stores, journals or native resources.
// A reused context cannot attach its old updater to a later/foreign holder.
// Cancellation does not hide progress: only the holder's release removes it.
func WithProgress(ctx context.Context, kind string) (context.Context, func(phase, serviceID string)) {
	noop := func(string, string) {}
	if ctx == nil {
		return nil, noop
	}
	if kind != "autonomy" {
		// Shadow an inherited tracker as well; unknown kinds expose no metadata.
		return context.WithValue(ctx, progressContextKey{}, (*progressTracker)(nil)), noop
	}
	p := &progressTracker{kind: kind}
	p.step.Store(&progressStep{phase: "preparing", since: time.Now()})
	update := func(phase, serviceID string) {
		if !validProgressPhase(phase) {
			return
		}
		if !validProgressServiceID(serviceID) {
			serviceID = ""
		}
		for {
			previous := p.step.Load()
			if previous.phase == phase && previous.serviceID == serviceID {
				return // Repeated reports cannot renew the age of the same phase.
			}
			next := &progressStep{phase: phase, serviceID: serviceID, since: time.Now()}
			if p.step.CompareAndSwap(previous, next) {
				return
			}
		}
	}
	return context.WithValue(ctx, progressContextKey{}, p), update
}

func validProgressPhase(phase string) bool {
	switch phase {
	case "preparing", "maintenance", "subscriptions", "selecting", "activating", "checking", "reserves", "cleanup", "update-handoff":
		return true
	default:
		return false
	}
}

func validProgressServiceID(id string) bool {
	if len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func bindProgress(ctx context.Context) *admittedProgress {
	p, _ := ctx.Value(progressContextKey{}).(*progressTracker)
	if p == nil || !p.claimed.CompareAndSwap(false, true) {
		return nil
	}
	deadline, ok := ctx.Deadline()
	return &admittedProgress{tracker: p, deadline: deadline, hasDeadline: ok}
}

func (p *admittedProgress) snapshot(id uint64, started, now time.Time) *Progress {
	if p == nil {
		return nil
	}
	step := p.tracker.step.Load()
	phaseStarted := step.since
	if phaseStarted.Before(started) {
		phaseStarted = started // Preparation before admission is not holder time.
	}
	value := &Progress{
		ID: id, Kind: p.tracker.kind, Phase: step.phase, ServiceID: step.serviceID,
		StartedAt: started.UTC(), PhaseStartedAt: phaseStarted.UTC(),
		ElapsedSeconds: max(0, int64(now.Sub(started)/time.Second)),
		PhaseSeconds:   max(0, int64(now.Sub(phaseStarted)/time.Second)),
	}
	if p.hasDeadline {
		deadline := p.deadline.UTC()
		value.DeadlineAt = &deadline
		value.DeadlineExceeded = !now.Before(p.deadline)
		remaining := p.deadline.Sub(now)
		seconds := max(0, int64(remaining/time.Second))
		if remaining > 0 && remaining%time.Second != 0 {
			seconds++ // A positive fraction still has time left in this budget.
		}
		value.RemainingSeconds = &seconds
	}
	return value
}
