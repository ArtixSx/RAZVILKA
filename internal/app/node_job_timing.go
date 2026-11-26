package app

import "time"

// nodeJobTiming is diagnostic RAM only. It grants no scheduling or route
// authority. Published values are immutable; each update replaces the pointer.
// EnqueuedAt comes from the existing durable journal, never a second queue.
type nodeJobTiming struct {
	Version         int        `json:"version"`
	EnqueuedAt      time.Time  `json:"enqueued_at"`
	FirstAdmittedAt *time.Time `json:"first_admitted_at,omitempty"`
	ObservedAt      time.Time  `json:"observed_at"`
	QueueWaitMS     *int64     `json:"queue_wait_ms"`
	TotalMS         *int64     `json:"total_ms"`
	TotalKind       string     `json:"total_kind"`
}

func nodeJobTimingView(enqueued time.Time, memory *nodeJobTiming, finished *time.Time, now time.Time) *nodeJobTiming {
	if enqueued.IsZero() {
		return nil
	}
	out := &nodeJobTiming{Version: 1, EnqueuedAt: enqueued, ObservedAt: now, TotalKind: "enqueue-to-server-observation"}
	if memory != nil && memory.FirstAdmittedAt != nil && !memory.FirstAdmittedAt.Before(enqueued) && !memory.FirstAdmittedAt.After(now) {
		admitted := *memory.FirstAdmittedAt
		out.FirstAdmittedAt = &admitted
		elapsed := admitted.Sub(enqueued).Milliseconds()
		out.QueueWaitMS = &elapsed
	}
	end := now
	if finished != nil {
		end = *finished
		out.TotalKind = "enqueue-to-server-completion"
	}
	if !end.Before(enqueued) && !end.After(now) && end.Sub(enqueued) <= 24*time.Hour {
		elapsed := end.Sub(enqueued).Milliseconds()
		out.TotalMS = &elapsed
	}
	return out
}
func (a *App) durableNodeEnqueuedAt(id uint64) time.Time {
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	for _, job := range a.reconciler.doc.Jobs {
		if job.ID == id && job.Request.Kind == "node-check" {
			return job.CreatedAt
		}
	}
	return time.Time{}
}
