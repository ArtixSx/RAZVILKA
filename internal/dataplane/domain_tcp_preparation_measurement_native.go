//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"sync"
	"time"
)

// Numeric/fixed-label diagnostics only. Resource is a bounded local ordinal,
// not a generation name, pointer, path, command or authority. command-run
// includes admission and the original runner's Start/Wait return;
// start-admission includes the original WithStart callback and its bookends.
// Neither marker independently proves durable receipt publication. Command
// rows use Index=-1 and can include cleanup; they do not infer direction.
// Parent fields describe the original Run context captured before Run, NOT a
// narrower tool/child context or the fixture publication window.
type DomainTCPNativePreparationStage struct {
	Resource, Index                             int
	Stage                                       string
	StartedOffset, FinishedOffset, Elapsed      time.Duration
	HasParentDeadline                           bool
	ParentRemainingStart, ParentRemainingFinish time.Duration
	ParentCanceledStart, ParentCanceledFinish   bool
	Completed, ReturnedError                    bool
}

type DomainTCPNativePreparationSnapshot struct {
	Stages  []DomainTCPNativePreparationStage
	Dropped int
}

var domainTCPPreparationMetrics struct {
	sync.Mutex
	active      bool
	generation  uint64
	start       time.Time
	deadline    time.Time
	hasDeadline bool
	done        <-chan struct{}
	resources   map[*domainTCPCaptureExecutionResource]int
	rows        []DomainTCPNativePreparationStage
	dropped     int
}

func domainTCPPreparationSnapshotLocked() DomainTCPNativePreparationSnapshot {
	return DomainTCPNativePreparationSnapshot{
		Stages:  append([]DomainTCPNativePreparationStage(nil), domainTCPPreparationMetrics.rows...),
		Dropped: domainTCPPreparationMetrics.dropped,
	}
}

// Start only alongside a single isolated original Run population. No context
// carrier is installed. Stop seals this generation; late completions cannot
// modify a later population or the returned snapshot.
func StartDomainTCPNativePreparationMeasurement(parent context.Context) func() DomainTCPNativePreparationSnapshot {
	if parent == nil {
		panic("missing preparation measurement parent")
	}
	// Called by the fixture BEFORE owner.Run, outside owner locks. These are
	// the only context interface calls made by this recorder.
	deadline, hasDeadline := parent.Deadline()
	done := parent.Done()
	domainTCPPreparationMetrics.Lock()
	if domainTCPPreparationMetrics.active {
		domainTCPPreparationMetrics.Unlock()
		panic("overlapping domain preparation measurements")
	}
	domainTCPPreparationMetrics.active = true
	domainTCPPreparationMetrics.generation++
	domainTCPPreparationMetrics.start = time.Now()
	domainTCPPreparationMetrics.deadline = deadline
	domainTCPPreparationMetrics.hasDeadline = hasDeadline
	domainTCPPreparationMetrics.done = done
	domainTCPPreparationMetrics.resources = make(map[*domainTCPCaptureExecutionResource]int)
	domainTCPPreparationMetrics.rows = nil
	domainTCPPreparationMetrics.dropped = 0
	domainTCPPreparationMetrics.Unlock()
	var once sync.Once
	var result DomainTCPNativePreparationSnapshot
	return func() DomainTCPNativePreparationSnapshot {
		once.Do(func() {
			domainTCPPreparationMetrics.Lock()
			defer domainTCPPreparationMetrics.Unlock()
			domainTCPPreparationMetrics.active = false
			result = domainTCPPreparationSnapshotLocked()
			domainTCPPreparationMetrics.resources = nil
			domainTCPPreparationMetrics.done = nil
		})
		return DomainTCPNativePreparationSnapshot{Stages: append([]DomainTCPNativePreparationStage(nil), result.Stages...), Dropped: result.Dropped}
	}
}

// Snapshot before the fixture cancels Run distinguishes an in-flight original
// preparation from errors joined during the subsequent original cleanup.
func DomainTCPNativePreparationMeasurementSnapshot() DomainTCPNativePreparationSnapshot {
	domainTCPPreparationMetrics.Lock()
	defer domainTCPPreparationMetrics.Unlock()
	return domainTCPPreparationSnapshotLocked()
}

type domainTCPPreparationMeasurement struct {
	entry *domainTCPPreparationMeasurementEntry
}
type domainTCPPreparationMeasurementEntry struct {
	once        sync.Once
	generation  uint64
	index       int
	done        <-chan struct{}
	start       time.Time
	deadline    time.Time
	hasDeadline bool
}

func domainTCPPreparationLabel(stage string, index int) bool {
	switch stage {
	case "apply-effects", "post-add-comparison", "phase-persist", "save-initial", "command-run", "start-admission", "capture-mapping-preparation-closing":
		return index == -1
	case "save-intent", "save-added":
		return index >= 0 && index < 7
	default:
		return false
	}
}

func domainTCPPreparationCanceled(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func domainTCPMeasurePreparation(resource *domainTCPCaptureExecutionResource, stage string, index int) domainTCPPreparationMeasurement {
	if resource == nil || !domainTCPPreparationLabel(stage, index) {
		return domainTCPPreparationMeasurement{}
	}
	domainTCPPreparationMetrics.Lock()
	defer domainTCPPreparationMetrics.Unlock()
	if !domainTCPPreparationMetrics.active {
		return domainTCPPreparationMeasurement{}
	}
	if len(domainTCPPreparationMetrics.rows) >= 96 {
		domainTCPPreparationMetrics.dropped++
		return domainTCPPreparationMeasurement{}
	}
	id := domainTCPPreparationMetrics.resources[resource]
	if id == 0 {
		if len(domainTCPPreparationMetrics.resources) >= 8 {
			domainTCPPreparationMetrics.dropped++
			return domainTCPPreparationMeasurement{}
		}
		id = len(domainTCPPreparationMetrics.resources) + 1
		domainTCPPreparationMetrics.resources[resource] = id
	}
	start := time.Now()
	deadline, hasDeadline, done := domainTCPPreparationMetrics.deadline, domainTCPPreparationMetrics.hasDeadline, domainTCPPreparationMetrics.done
	row := DomainTCPNativePreparationStage{Resource: id, Index: index, Stage: stage,
		StartedOffset: start.Sub(domainTCPPreparationMetrics.start), HasParentDeadline: hasDeadline, ParentCanceledStart: domainTCPPreparationCanceled(done)}
	if hasDeadline {
		row.ParentRemainingStart = deadline.Sub(start)
	}
	entry := &domainTCPPreparationMeasurementEntry{generation: domainTCPPreparationMetrics.generation,
		index: len(domainTCPPreparationMetrics.rows), done: done, start: start, deadline: deadline, hasDeadline: hasDeadline}
	domainTCPPreparationMetrics.rows = append(domainTCPPreparationMetrics.rows, row)
	return domainTCPPreparationMeasurement{entry: entry}
}

func (m domainTCPPreparationMeasurement) end(err error) error {
	if m.entry == nil {
		return err
	}
	e := m.entry
	e.once.Do(func() {
		end := time.Now()
		// No error/context interface calls: the original caller can hold owner
		// locks. Wrapped error causes remain intentionally unclassified.
		ctxCanceled := domainTCPPreparationCanceled(e.done)
		domainTCPPreparationMetrics.Lock()
		defer domainTCPPreparationMetrics.Unlock()
		if !domainTCPPreparationMetrics.active || domainTCPPreparationMetrics.generation != e.generation {
			return
		}
		r := &domainTCPPreparationMetrics.rows[e.index]
		r.Completed, r.ReturnedError = true, err != nil
		r.ParentCanceledFinish = ctxCanceled
		r.Elapsed, r.FinishedOffset = end.Sub(e.start), end.Sub(domainTCPPreparationMetrics.start)
		if e.hasDeadline {
			r.ParentRemainingFinish = e.deadline.Sub(end)
		}
	})
	return err
}

func (m domainTCPPreparationMeasurement) bytes(data []byte, err error) ([]byte, error) {
	return data, m.end(err)
}

func domainTCPMeasurePreparationCommand(runner *domainTCPCaptureEffectRunner, stage string) domainTCPPreparationMeasurement {
	if runner == nil || runner.resource == nil {
		return domainTCPPreparationMeasurement{}
	}
	// No context.Value lookup and no inferred cleanup direction/command index.
	// Original save-intent/save-added rows separately retain their exact index.
	return domainTCPMeasurePreparation(runner.resource, stage, -1)
}

func domainTCPMeasurePreparationSave(s *policyEffectSession) domainTCPPreparationMeasurement {
	if s == nil || s.policyAdditionSession == nil || s.domainPreAdd == nil || s.domainPreAdd.capture == nil || len(s.doc.Steps) != 7 {
		return domainTCPPreparationMeasurement{}
	}
	stage, index := "save-initial", -1
	// The original synchronous COMMON writer owns these step fields. Cleanup
	// sessions do not carry this pre-Add producer and are deliberately excluded.
	for n, step := range s.doc.Steps {
		switch step.State {
		case "planned":
		case "intent":
			stage, index = "save-intent", n
		case "added":
			stage, index = "save-added", n
		default:
			return domainTCPPreparationMeasurement{}
		}
	}
	return domainTCPMeasurePreparation(s.domainPreAdd.capture, stage, index)
}
