package app

import "time"

// Priority is derived from accepted intent, never a client-supplied number.
// Aging uses persisted acceptance time so restart cannot make a waiting batch
// young again. It cannot overtake Stop or make a not-before job runnable.
func durableJobPriority(job durableServiceJob, now time.Time) int {
	if job.Request.Kind == "stop" {
		return 0
	}
	priority := 2
	switch job.Request.Kind {
	case "resume", "node-apply", "dns-apply":
		priority = 1
	case "node-check":
		if len(job.Request.NodeIDs) > 1 || job.Request.NodeCatalog != nil {
			priority = 4
		}
	case "check", "auto":
		if len(job.Request.ServiceIDs) > 1 {
			priority = 4
		}
	}
	if now.After(job.CreatedAt) {
		priority = max(1, priority-int(min(now.Sub(job.CreatedAt)/(2*time.Minute), 3)))
	}
	return priority
}

func selectDurableServiceJob(jobs []durableServiceJob, now time.Time, recoveryDue bool) int {
	index := -1
	for i, job := range jobs {
		if job.State != "queued" && job.State != "interrupted" || now.Before(job.NotBefore) {
			continue
		}
		if job.Request.Kind == "node-check" && recoveryDue {
			continue
		}
		if index < 0 {
			index = i
			continue
		}
		best := jobs[index]
		priority, bestPriority := durableJobPriority(job, now), durableJobPriority(best, now)
		if priority < bestPriority || priority == bestPriority && (job.CreatedAt.Before(best.CreatedAt) || job.CreatedAt.Equal(best.CreatedAt) && job.ID < best.ID) {
			index = i
		}
	}
	return index
}
