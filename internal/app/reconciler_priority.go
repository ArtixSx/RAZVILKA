package app

import (
	"cmp"
	"slices"
	"time"
)

// A round yields only after a task has joined its transaction/checker cleanup.
// This is a dispatch quantum, never a shortened transaction deadline.
const reconcilerDispatchQuantum = time.Second

type reconcilerTask struct {
	kind     string
	interval time.Duration
}

func orderedReconcilerTasks(tasks []reconcilerTask, operations []automationOperation, now time.Time) []reconcilerTask {
	due := make(map[string]time.Time, len(operations))
	for _, op := range operations {
		due[op.Kind] = op.NextRun
	}
	base := map[string]int{"node-recovery": 0, "node-fallback": 1, "legacy-routes": 2, "feeds": 3, "service-checks": 4}
	priority := func(kind string) int {
		p := base[kind]
		if at := due[kind]; !at.IsZero() && now.After(at) {
			p = max(0, p-int(min(now.Sub(at)/(2*time.Minute), 4)))
		}
		return p
	}
	result := slices.Clone(tasks)
	slices.SortStableFunc(result, func(a, b reconcilerTask) int {
		if p := cmp.Compare(priority(a.kind), priority(b.kind)); p != 0 {
			return p
		}
		at, bt := due[a.kind], due[b.kind]
		if at.IsZero() {
			at = now
		}
		if bt.IsZero() {
			bt = now
		}
		return at.Compare(bt)
	})
	return result
}
