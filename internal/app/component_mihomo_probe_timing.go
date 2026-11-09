package app

import "time"

// Diagnostic durations for one synchronous probe handler, never evidence or
// queue arrival. The total ends before response serialization; middleware,
// network delivery and the handler's deferred notifications are not measured.
// Missing phases were not attempted; an observed sub-millisecond phase is 0.
type mihomoProbeAttemptTiming struct {
	HandlerElapsedMS int64  `json:"handler_elapsed_ms"`
	PreparationMS    int64  `json:"preparation_ms"`
	AdapterCheckMS   *int64 `json:"adapter_check_ms,omitempty"`
	PostcheckMS      *int64 `json:"postcheck_ms,omitempty"`
	FinalizeMS       *int64 `json:"finalize_ms,omitempty"`
	started          time.Time
	prepared         bool
}

func (m *mihomoProbeAttemptTiming) finishPreparation() {
	if !m.prepared {
		m.PreparationMS = max(0, time.Since(m.started).Milliseconds())
		m.prepared = true
	}
}

func (m *mihomoProbeAttemptTiming) snapshot() *mihomoProbeAttemptTiming {
	if m == nil {
		return nil
	}
	m.finishPreparation()
	copy := *m
	copy.HandlerElapsedMS = max(0, time.Since(m.started).Milliseconds())
	return &copy
}

// Runs the original operation once, synchronously, retaining its exact error.
// In particular, measuring a failed close never grants cleanup confirmation.
func measureMihomoProbePhase(duration **int64, use func() error) error {
	started := time.Now()
	defer func() {
		elapsed := max(0, time.Since(started).Milliseconds())
		*duration = &elapsed
	}()
	return use()
}
