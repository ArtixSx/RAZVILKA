//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DomainTCPNativeForwardStage is a bounded request-local diagnostic, not a
// policy decision or proof. Request is an ordinal for the existing accepted
// carrier, never an address, domain, pointer, FlowID or other private value.
// Offsets start at StartDomainTCPNativeMeasurement, not the client request.
// ContextRemaining is the server context deadline, NOT the client's 4s limit.
type DomainTCPNativeForwardStage struct {
	Request                                                int
	Boundary, Stage                                        string
	StartedOffset, FinishedOffset, Elapsed                 time.Duration
	HasContextDeadline                                     bool
	ContextRemainingStart, ContextRemainingFinish          time.Duration
	ContextCanceledStart, ContextCanceledFinish            bool
	Completed, ReturnedError, ErrorCanceled, ErrorDeadline bool
}

type DomainTCPNativeForwardSnapshot struct {
	Stages  []DomainTCPNativeForwardStage
	Dropped int
}

func DomainTCPNativeForwardMeasurementSnapshot() DomainTCPNativeForwardSnapshot {
	domainTCPNativeMetrics.Lock()
	defer domainTCPNativeMetrics.Unlock()
	return DomainTCPNativeForwardSnapshot{
		Stages:  append([]DomainTCPNativeForwardStage(nil), domainTCPNativeMetrics.forwardRows...),
		Dropped: domainTCPNativeMetrics.forwardDropped,
	}
}

func domainTCPMeasureForwardStage(ctx context.Context, boundary, stage string) func(error) {
	if ctx == nil || (boundary != "pre-dial" && boundary != "post-dial") || (stage != "guard" && stage != "decision" && stage != "compare") {
		return func(error) {}
	}
	accepted, _ := ctx.Value(domainAcceptedTCPKey{}).(*domainAcceptedTCP)
	if accepted == nil || accepted.self != accepted || !accepted.open.Load() {
		return func(error) {}
	}
	deadline, hasDeadline := ctx.Deadline()
	contextCanceled := ctx.Err() != nil
	domainTCPNativeMetrics.Lock()
	if !domainTCPNativeMetrics.active {
		domainTCPNativeMetrics.Unlock()
		return func(error) {}
	}
	id := domainTCPNativeMetrics.forwardIDs[accepted]
	if id == 0 {
		if len(domainTCPNativeMetrics.forwardIDs) >= 32 {
			domainTCPNativeMetrics.forwardDropped++
			domainTCPNativeMetrics.Unlock()
			return func(error) {}
		}
		id = len(domainTCPNativeMetrics.forwardIDs) + 1
		domainTCPNativeMetrics.forwardIDs[accepted] = id
	}
	if domainTCPNativeMetrics.forwardCounts[id] >= 8 {
		domainTCPNativeMetrics.forwardDropped++
		domainTCPNativeMetrics.Unlock()
		return func(error) {}
	}
	domainTCPNativeMetrics.forwardCounts[id]++
	start := time.Now()
	row := DomainTCPNativeForwardStage{Request: id, Boundary: boundary, Stage: stage,
		StartedOffset:      start.Sub(domainTCPNativeMetrics.forwardStart),
		HasContextDeadline: hasDeadline, ContextCanceledStart: contextCanceled}
	if hasDeadline {
		row.ContextRemainingStart = deadline.Sub(start)
	}
	index, generation := len(domainTCPNativeMetrics.forwardRows), domainTCPNativeMetrics.generation
	domainTCPNativeMetrics.forwardRows = append(domainTCPNativeMetrics.forwardRows, row)
	domainTCPNativeMetrics.Unlock()
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			end := time.Now()
			// Interface methods can re-enter diagnostics. Never run them while
			// holding the shared snapshot mutex.
			errorCanceled := errors.Is(err, context.Canceled)
			errorDeadline := errors.Is(err, context.DeadlineExceeded)
			contextCanceled := ctx.Err() != nil
			domainTCPNativeMetrics.Lock()
			defer domainTCPNativeMetrics.Unlock()
			if !domainTCPNativeMetrics.active || domainTCPNativeMetrics.generation != generation {
				return
			}
			r := &domainTCPNativeMetrics.forwardRows[index]
			r.Completed, r.ReturnedError = true, err != nil
			r.ErrorCanceled, r.ErrorDeadline = errorCanceled, errorDeadline
			r.Elapsed, r.FinishedOffset = end.Sub(start), end.Sub(domainTCPNativeMetrics.forwardStart)
			r.ContextCanceledFinish = contextCanceled
			if hasDeadline {
				r.ContextRemainingFinish = deadline.Sub(end)
			}
		})
	}
}
