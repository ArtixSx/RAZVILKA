package providerfeed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

const MaxJobs = 32

type Job struct {
	ID         string    `json:"id"`
	SourceID   string    `json:"source_id"`
	Status     string    `json:"status"`
	Scheduled  bool      `json:"scheduled"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Result     *Result   `json:"result,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
}
type jobEntry struct {
	view   Job
	cancel context.CancelFunc
}
type jobState struct {
	entries  map[string]*jobEntry
	order    []string
	queue    []string
	wake     chan struct{}
	done     chan struct{}
	started  bool
	stopping bool
}

// Start owns all asynchronous work until Wait returns. Admission must be a
// fresh application operation lease, not a request context's expired lease.
func (m *Manager) Start(ctx context.Context, admission func(context.Context) (func(), error)) {
	m.start(ctx, admission, false)
}

// StartManaged keeps the bounded worker but delegates periodic due decisions
// to the application reconciler. Manual refreshes still wake this same queue.
func (m *Manager) StartManaged(ctx context.Context, admission func(context.Context) (func(), error)) {
	m.start(ctx, admission, true)
}

func (m *Manager) start(ctx context.Context, admission func(context.Context) (func(), error), managed bool) {
	m.mu.Lock()
	if m.jobs.started || m.closed || m.storage == nil {
		m.mu.Unlock()
		return
	}
	m.jobs = jobState{entries: map[string]*jobEntry{}, wake: make(chan struct{}, 1), done: make(chan struct{}), started: true}
	m.mu.Unlock()
	go m.runJobs(ctx, admission, managed)
}

func (m *Manager) ScheduleDue(now time.Time) {
	for _, id := range m.Due(now) {
		m.mu.Lock()
		if m.jobs.started && !m.jobs.stopping {
			_, _ = m.queueLocked(id, true)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) Wait(ctx context.Context) error {
	m.mu.Lock()
	done := m.jobs.done
	m.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Scheduling() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs.started && !m.jobs.stopping && !m.closed && !m.fenced
}

func (m *Manager) QueueSync(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queueLocked(id, false)
}

func (m *Manager) queueLocked(id string, scheduled bool) (Job, error) {
	if m.closed || m.fenced || !m.jobs.started || m.jobs.stopping {
		return Job{}, ErrStore
	}
	if m.sourceIndexLocked(id) < 0 {
		return Job{}, ErrNotFound
	}
	for _, entry := range m.jobs.entries {
		if entry.view.SourceID == id && (entry.view.Status == "queued" || entry.view.Status == "running") {
			return entry.view, nil
		}
	}
	if len(m.jobs.queue) >= MaxFeeds {
		return Job{}, ErrBusy
	}
	for len(m.jobs.entries) >= MaxJobs {
		removed := false
		for i, old := range m.jobs.order {
			e := m.jobs.entries[old]
			if e.view.Status != "queued" && e.view.Status != "running" {
				delete(m.jobs.entries, old)
				m.jobs.order = append(m.jobs.order[:i], m.jobs.order[i+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			return Job{}, ErrBusy
		}
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Job{}, ErrStore
	}
	job := Job{ID: "feedjob-" + hex.EncodeToString(nonce[:]), SourceID: id, Status: "queued", Scheduled: scheduled, CreatedAt: m.now().UTC()}
	m.jobs.entries[job.ID] = &jobEntry{view: job}
	m.jobs.order = append(m.jobs.order, job.ID)
	m.jobs.queue = append(m.jobs.queue, job.ID)
	select {
	case m.jobs.wake <- struct{}{}:
	default:
	}
	return job, nil
}

func (m *Manager) Job(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.jobs.entries[id]
	if entry == nil {
		return Job{}, ErrNotFound
	}
	view := entry.view
	if view.Result != nil {
		r := *view.Result
		r.NodeIDs = append([]string(nil), r.NodeIDs...)
		r.Issues = append(r.Issues[:0:0], r.Issues...)
		view.Result = &r
	}
	return view, nil
}
func (m *Manager) CancelJob(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.jobs.entries[id]
	if entry == nil {
		return Job{}, ErrNotFound
	}
	if entry.view.Status == "queued" {
		entry.view.Status = "canceled"
		entry.view.FinishedAt = m.now().UTC()
	}
	if entry.cancel != nil {
		entry.cancel()
	}
	return entry.view, nil
}

func (m *Manager) runJobs(ctx context.Context, admission func(context.Context) (func(), error), managed bool) {
	var ticks <-chan time.Time
	if !managed {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		ticks = ticker.C
	}
	// Startup recovery and HTTP readiness have priority. The durable due time
	// is retained; overdue subscriptions spread through one bounded queue.
	scheduleAfter := m.now().Add(time.Minute)
	defer func() {
		m.mu.Lock()
		m.jobs.stopping = true
		for _, e := range m.jobs.entries {
			if e.view.Status == "queued" {
				e.view.Status = "canceled"
				e.view.FinishedAt = m.now().UTC()
			}
		}
		close(m.jobs.done)
		m.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if !m.now().Before(scheduleAfter) {
				for _, id := range m.Due(m.now()) {
					m.mu.Lock()
					_, _ = m.queueLocked(id, true)
					m.mu.Unlock()
				}
			}
		case <-m.jobs.wake:
		}
		for {
			if ctx.Err() != nil {
				return
			}
			m.mu.Lock()
			if len(m.jobs.queue) == 0 {
				m.mu.Unlock()
				break
			}
			id := m.jobs.queue[0]
			m.jobs.queue = m.jobs.queue[1:]
			entry := m.jobs.entries[id]
			if entry == nil || entry.view.Status != "queued" {
				m.mu.Unlock()
				continue
			}
			if entry.view.Scheduled {
				i := m.sourceIndexLocked(entry.view.SourceID)
				if i < 0 || !m.storage.doc.Sources[i].Enabled {
					entry.view.Status = "canceled"
					entry.view.FinishedAt = m.now().UTC()
					m.mu.Unlock()
					continue
				}
			}
			jobCtx, cancel := context.WithTimeout(ctx, Timeout+5*time.Second)
			entry.view.Status = "running"
			entry.view.StartedAt = m.now().UTC()
			entry.cancel = cancel
			sourceID := entry.view.SourceID
			m.mu.Unlock()
			release := func() {}
			var err error
			if admission != nil {
				release, err = admission(jobCtx)
			}
			var result Result
			if err == nil {
				result, err = m.SyncSaved(jobCtx, sourceID)
				release()
			}
			cancel()
			m.mu.Lock()
			entry.cancel = nil
			entry.view.FinishedAt = m.now().UTC()
			entry.view.Result = &result
			entry.view.ErrorCode = ErrorCode(err)
			entry.view.Status = "completed"
			if err != nil {
				entry.view.Status = "failed"
			}
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				entry.view.Status = "canceled"
			}
			m.mu.Unlock()
		}
	}
}
