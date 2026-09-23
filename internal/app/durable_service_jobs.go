package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const maxDurableServiceJobs = 64
const durableJobRetention = 24 * time.Hour

var errDurableKeyConflict = errors.New("idempotency key has different intent")
var errDurableQueueFull = errors.New("durable queue is full")

// Kept in the existing reconciler document, never a second journal/worker.
// Only references and fingerprints are durable: profiles, keys, probe bodies,
// cached PASS and permission to replay a network transaction are not stored.
type durableServiceJob struct {
	ID              uint64                   `json:"id"`
	KeyHash         string                   `json:"key_hash"`
	KeyAliases      []string                 `json:"key_aliases,omitempty"`
	RequestHash     string                   `json:"request_hash"`
	IntentHash      string                   `json:"intent_hash"`
	Request         serviceControlJobRequest `json:"request"`
	State           string                   `json:"state"`
	Phase           string                   `json:"phase"`
	Reason          string                   `json:"reason"`
	CreatedAt       time.Time                `json:"created_at"`
	ExpiresAt       time.Time                `json:"expires_at"`
	NotBefore       time.Time                `json:"not_before"`
	Deadline        time.Time                `json:"deadline"`
	FinishedAt      *time.Time               `json:"finished_at,omitempty"`
	Attempts        int                      `json:"attempts"`
	Cursor          int                      `json:"cursor"`
	CancelRequested bool                     `json:"cancel_requested"`
	CleanupOutcome  string                   `json:"cleanup_outcome"`
	RuntimeCode     string                   `json:"runtime_code,omitempty"`
	DNSCode         string                   `json:"dns_code,omitempty"`
	NodeCode        string                   `json:"node_code,omitempty"`
	NodeReview      *durableNodeReview       `json:"node_review,omitempty"`
	CheckNetwork    string                   `json:"check_network,omitempty"`
}

func (j durableServiceJob) terminal() bool {
	return j.State == "completed" || j.State == "failed" || j.State == "canceled"
}

func (j durableServiceJob) presentation() *nodeCheckJob {
	message := "Задание сохранено на роутере и ожидает запуска. Браузер можно закрыть."
	switch j.State {
	case "running":
		message = "Проверка выполняется на роутере."
	case "canceling":
		message = "Отмена сохранена; ожидаем завершения очистки."
	case "interrupted":
		message = "После перезапуска проверим актуальность задания и выполним новую проверку."
	case "completed":
		message = "Задание завершено. Доступность сервиса определяется отдельным свежим результатом."
	case "failed":
		message = "Задание не выполнено: изменились условия или проверка не завершилась."
	case "canceled":
		message = "Задание отменено."
	}
	total, completed, code := len(j.Request.ServiceIDs), j.Cursor, j.Reason
	if j.Request.Kind == "dns-compare" {
		message = dnsJobMessage(j)
		if j.DNSCode != "" {
			code = j.DNSCode
		}
	}
	if isRuntimeJob(j.Request.Kind) {
		total = 1
		if j.State == "completed" {
			completed = 1
		}
		message = runtimeJobMessage(j)
		if j.RuntimeCode != "" {
			code = j.RuntimeCode
		}
	}
	if j.Request.Kind == "node-apply" {
		total, completed, message = 1, 0, nodeApplyJobMessage(j)
		if j.State == "completed" {
			completed = 1
		}
		if j.NodeCode != "" {
			code = j.NodeCode
		}
	}
	p := &nodeCheckJob{ID: j.ID, Mode: "service-" + j.Request.Kind, State: j.State, Phase: j.Phase,
		ErrorCode: code, Total: total, Completed: completed,
		StartedAt: j.CreatedAt, FinishedAt: j.FinishedAt, Message: message, Results: []nodeCheckItem{}}
	if j.Request.Kind == "node-check" {
		p.Mode, p.Total = j.Request.NodeCheckMode, len(j.Request.NodeIDs)
		if j.Cursor > 0 {
			p.ResultState = "not-retained"
		}
		if j.State == "failed" {
			p.Message = durableNodeCheckFailureMessage(j.Reason)
		}
		if c := j.Request.NodeCatalog; c != nil {
			p.Scope, p.Matched, p.Skipped = allVLESSScope, c.Matched, c.Matched-len(j.Request.NodeIDs)
		}
		if len(j.Request.ServiceIDs) == 1 {
			p.ServiceID = j.Request.ServiceIDs[0]
		}
		if j.State == "completed" {
			p.Message = "Проверка подключений завершена. Маршруты не применялись; результаты имеют ограниченный срок."
		}
	}
	if j.Request.Kind == "dns-compare" && validDurableDNSRequest(j.Request) {
		revision := *j.Request.ExpectedRevision
		p.DNSRequest = &serviceDNSCompareRequest{ServiceID: j.Request.ServiceIDs[0], ProfileIDs: slices.Clone(j.Request.DNS.ProfileIDs), ConfigRevision: &revision, VerifyService: j.Request.DNS.VerifyService}
	}
	return p
}

func validJobHash(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

func validateDurableServiceJobs(jobs []durableServiceJob) error {
	if len(jobs) > maxDurableServiceJobs {
		return restorejournal.ErrInvalid
	}
	ids, keys := map[uint64]bool{}, map[string]bool{}
	for _, j := range jobs {
		if j.CheckNetwork != "" && (j.Request.Kind != "node-check" || !validJobHash(j.CheckNetwork)) {
			return restorejournal.ErrInvalid
		}
		if !validDurableNodeReview(j) {
			return restorejournal.ErrInvalid
		}
		if !validDNSJobCode(j.DNSCode) || j.DNSCode != "" && j.Request.Kind != "dns-compare" {
			return restorejournal.ErrInvalid
		}
		if !validRuntimeJobCode(j.RuntimeCode) || j.RuntimeCode != "" && !isRuntimeJob(j.Request.Kind) {
			return restorejournal.ErrInvalid
		}
		if j.ID == 0 || j.ID >= 1<<49 || ids[j.ID] || keys[j.KeyHash] || !validJobHash(j.KeyHash) || !validJobHash(j.RequestHash) || !validJobHash(j.IntentHash) || j.Request.IdempotencyKey != "" || !validDurableRequest(j.Request) || j.Attempts < 0 || j.Attempts > 3 || j.Cursor < 0 || j.Cursor > durableJobTotal(j.Request) || j.CreatedAt.IsZero() || !j.ExpiresAt.After(j.CreatedAt) || j.ExpiresAt.Sub(j.CreatedAt) > 24*time.Hour {
			return restorejournal.ErrInvalid
		}
		if !slices.Contains([]string{"queued", "running", "canceling", "interrupted", "completed", "failed", "canceled"}, j.State) || !slices.Contains([]string{"waiting", "checking", "cleanup", "done"}, j.Phase) || !slices.Contains([]string{"", "accepted", "startup-reconcile", "settings-changed", "expired", "attempt-limit", "check-failed", "canceled", "cleanup-unverified", "interrupted", "check-timeout", "network-unconfirmed", "node-store-unavailable"}, j.Reason) || !slices.Contains([]string{"not-started", "pending", "joined", "startup-recovered", "unverified"}, j.CleanupOutcome) {
			return restorejournal.ErrInvalid
		}
		ids[j.ID], keys[j.KeyHash] = true, true
		if len(j.KeyAliases) > 8 {
			return restorejournal.ErrInvalid
		}
		for _, alias := range j.KeyAliases {
			if !validJobHash(alias) || keys[alias] {
				return restorejournal.ErrInvalid
			}
			keys[alias] = true
		}
	}
	return nil
}

func validDurableRequest(r serviceControlJobRequest) bool {
	if r.Kind == "node-check" {
		return validDurableNodeCheck(r)
	}
	if r.NodeCheckMode != "" || r.NodeCatalog != nil || r.resolveNodeCatalog {
		return false
	}
	if r.Kind == "node-apply" {
		return validDurableNodeApply(r)
	}
	if r.NodeApply != nil {
		return false
	}
	if r.Kind == "dns-compare" {
		return validDurableDNSRequest(r)
	}
	if r.DNS != nil {
		return false
	}
	if isRuntimeJob(r.Kind) {
		return r.ExpectedRevision != nil && len(r.ServiceIDs) == 0 && len(r.NodeIDs) == 0
	}
	if r.ExpectedRevision == nil || len(r.ServiceIDs) == 0 || len(r.ServiceIDs) > config.MaxScheduledServices || len(r.NodeIDs) > 3 || r.Kind != "check" && r.Kind != "select" || r.Kind == "check" && len(r.NodeIDs) != 0 || r.Kind == "select" && len(r.ServiceIDs) > 12 {
		return false
	}
	for _, list := range [][]string{r.ServiceIDs, r.NodeIDs} {
		seen := map[string]bool{}
		for _, id := range list {
			if id == "" || len(id) > 128 || seen[id] || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != "" {
				return false
			}
			seen[id] = true
		}
	}
	return true
}

func durableServiceIntentHash(cfg config.Config, services []catalog.Service) string {
	return applyReviewHash(struct {
		Config   config.Config
		Services []catalog.Service
	}{cfg, services})
}

func finishDurableJob(j *durableServiceJob, state, reason string, now time.Time) {
	j.State, j.Phase, j.Reason = state, "done", reason
	finished := now.UTC()
	j.FinishedAt = &finished
}

func recoverDurableServiceJobs(doc *reconcilerDocument, now time.Time) {
	for i := range doc.Jobs {
		j := &doc.Jobs[i]
		if j.terminal() {
			continue
		}
		if j.Request.Kind == "node-apply" {
			// Startup transaction recovery owns any unfinished rollback. A saved
			// review is not permission to replay activation in a new process.
			finishDurableJob(j, "failed", "startup-reconcile", now)
			j.NodeCode, j.CleanupOutcome = "NODE_REVIEW_CHANGED", "startup-recovered"
			continue
		}
		j.Cursor = 0 // Previous-process results do not prove the current network.
		j.CheckNetwork = ""
		if j.CancelRequested {
			finishDurableJob(j, "canceled", "canceled", now)
			j.CleanupOutcome = "startup-recovered"
		} else if j.State == "running" || j.State == "canceling" || j.State == "interrupted" {
			j.State, j.Phase, j.Reason = "interrupted", "waiting", "startup-reconcile"
			j.NotBefore, j.Cursor = now.Add(30*time.Second), 0
			j.CleanupOutcome = "startup-recovered"
		}
	}
}

func (a *App) enqueueDurableServiceJob(ctx context.Context, request serviceControlJobRequest) (durableServiceJob, error) {
	if !validDurableRequest(request) || len(request.IdempotencyKey) < 16 || len(request.IdempotencyKey) > 128 || strings.Trim(request.IdempotencyKey, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return durableServiceJob{}, errServiceControlRequest
	}
	key := applyReviewHash(request.IdempotencyKey)
	nodeToken, nodeOwner := request.nodeReviewToken, request.nodeReviewOwner
	request.nodeReviewToken, request.nodeReviewOwner = "", [32]byte{}
	request.IdempotencyKey = ""
	revision := *request.ExpectedRevision
	request.ExpectedRevision = &revision
	request.ServiceIDs, request.NodeIDs = slices.Clone(request.ServiceIDs), slices.Clone(request.NodeIDs)
	if request.DNS != nil {
		request.DNS = &serviceDNSJobSpec{ProfileIDs: slices.Clone(request.DNS.ProfileIDs), VerifyService: request.DNS.VerifyService}
	}
	if request.NodeApply != nil {
		copied := *request.NodeApply
		request.NodeApply = &copied
	}
	if request.NodeCatalog != nil {
		copied := *request.NodeCatalog
		request.NodeCatalog = &copied
	}
	fingerprint := durableRequestFingerprint(request)
	r := &a.reconciler
	lookup := func() (durableServiceJob, bool, error) {
		if !r.started || r.path == "" || r.blocked {
			return durableServiceJob{}, true, restorejournal.ErrRecovery
		}
		for _, j := range r.doc.Jobs {
			if j.KeyHash == key || slices.Contains(j.KeyAliases, key) {
				if j.RequestHash != fingerprint {
					return durableServiceJob{}, true, errDurableKeyConflict
				}
				return j, true, nil
			}
		}
		// Two windows may use different tokens for the same in-flight action.
		// Persist the alias before acknowledging it, including lost responses.
		for i := range r.doc.Jobs {
			j := &r.doc.Jobs[i]
			if !j.terminal() && j.RequestHash == fingerprint {
				if len(j.KeyAliases) >= 8 {
					return durableServiceJob{}, true, errDurableQueueFull
				}
				before := slices.Clone(j.KeyAliases)
				j.KeyAliases = append(slices.Clone(j.KeyAliases), key)
				if !durableQueueHasSpace(r.doc, j.Request.Kind == "stop") {
					j.KeyAliases = before
					return durableServiceJob{}, true, errDurableQueueFull
				}
				if err := a.persistReconcilerLocked(ctx); err != nil {
					j.KeyAliases = before
					return durableServiceJob{}, true, err
				}
				return *j, true, nil
			}
		}
		return durableServiceJob{}, false, nil
	}
	r.mu.Lock()
	job, found, err := lookup()
	r.mu.Unlock()
	if found {
		return job, err
	} // A retry must succeed even while its job owns admission.
	intent := fingerprint
	var nodeReview *durableNodeReview
	if request.Kind == "node-check" {
		intent, err = a.prepareDurableNodeCheck(ctx, &request)
		if err != nil {
			return durableServiceJob{}, err
		}
	} else if request.Kind == "node-apply" {
		nodeReview, intent, err = a.prepareDurableNodeApply(ctx, request, nodeToken, nodeOwner)
		if err != nil {
			return durableServiceJob{}, err
		}
	} else if isRuntimeJob(request.Kind) {
		// The immutable intent is exactly action + expected revision, not a
		// partially applied Store snapshot. The executor validates that revision
		// and its committed route scope after admission. No Store reads here.
		if a.Operations.Snapshot().Fenced {
			return durableServiceJob{}, operationgate.ErrRecovery
		}
		if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
			return durableServiceJob{}, operationgate.ErrBusy
		}
	} else {
		release, err := a.Operations.Exclusive(ctx)
		if err != nil {
			return durableServiceJob{}, err
		}
		if a.Store == nil {
			release()
			return durableServiceJob{}, errServiceControlRequest
		}
		cfg := a.Store.Get()
		services := []catalog.Service{}
		cat := a.catalogSnapshot()
		for _, id := range request.ServiceIDs {
			for _, service := range cat.Services {
				if service.ID == id {
					services = append(services, service)
					break
				}
			}
		}
		intent = durableServiceIntentHash(cfg, services)
		if request.Kind == "dns-compare" {
			intent, err = a.durableDNSIntentHash(cfg, services, request.DNS)
			if err != nil {
				release()
				return durableServiceJob{}, err
			}
		}
		release()
		if cfg.Revision != *request.ExpectedRevision {
			return durableServiceJob{}, config.ErrRevisionChanged
		}
		if len(services) != len(request.ServiceIDs) {
			return durableServiceJob{}, errServiceControlRequest
		}
	}
	r.mu.Lock()
	acceptedStop := false
	defer func() {
		r.mu.Unlock()
		if acceptedStop {
			a.preemptForRuntimeStop(job.ID)
		}
	}()
	if job, found, err = lookup(); found {
		return job, err
	}
	if request.Kind == "node-check" && a.Operations.Snapshot().Fenced {
		return durableServiceJob{}, operationgate.ErrRecovery
	}
	now := time.Now().UTC()
	retained := make([]durableServiceJob, 0, len(r.doc.Jobs)+1)
	pending := 0
	for _, j := range r.doc.Jobs {
		if !j.terminal() {
			pending++
		}
		if !j.terminal() || j.FinishedAt == nil || now.Sub(*j.FinishedAt) < durableJobRetention {
			retained = append(retained, j)
		}
	}
	// Reserve admission for one manual Stop even when bulk observations fill
	// the queue. Existing retained keys are never evicted early for this slot.
	capacity, pendingCapacity := maxDurableServiceJobs-1, 15
	if request.Kind == "stop" {
		capacity, pendingCapacity = maxDurableServiceJobs, 16
	}
	if len(retained) >= capacity || pending >= pendingCapacity {
		return durableServiceJob{}, errDurableQueueFull
	}
	var seed [8]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return durableServiceJob{}, err
	}
	id := 1 + (binary.LittleEndian.Uint64(seed[:]) & ((1 << 48) - 1))
	for _, existing := range retained {
		if existing.ID == id {
			return durableServiceJob{}, errDurableQueueFull
		}
	}
	job = durableServiceJob{ID: id, KeyHash: key, RequestHash: fingerprint, IntentHash: intent, Request: request,
		State: "queued", Phase: "waiting", Reason: "accepted", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), CleanupOutcome: "not-started", NodeReview: nodeReview}
	proposed := r.doc
	proposed.Jobs = append(retained, job)
	if !durableQueueHasSpace(proposed, request.Kind == "stop") {
		return durableServiceJob{}, errDurableQueueFull
	}
	previous := r.doc.Jobs
	previousManualUntil := r.doc.ManualUntil
	if nodeReview != nil {
		r.doc.ManualUntil = time.Time{}
	} // This reviewed manual action is now accepted.
	r.doc.Jobs = append(retained, job)
	if err = a.persistReconcilerLocked(ctx); err != nil {
		r.doc.Jobs = previous
		r.doc.ManualUntil = previousManualUntil
		return durableServiceJob{}, err
	}
	if nodeReview != nil {
		a.nodeReviews.take(nodeToken, nodeOwner, now)
	}
	acceptedStop = request.Kind == "stop"
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return job, nil
}

// Account for bytes before mutating the journal, in addition to job counts.
// Keep room for running/cleanup timestamps, terminal outcomes and manual Stop.
func durableQueueHasSpace(doc reconcilerDocument, stop bool) bool {
	reserve := 32 << 10
	if stop {
		reserve = 16 << 10
	}
	raw, err := json.Marshal(doc)
	return err == nil && len(raw) <= maxReconcilerBytes-reserve
}

func (a *App) addDurableServiceJobs(view map[string]any) {
	observations := a.nodeBatchMemoryResults()
	r := &a.reconciler
	r.mu.Lock()
	defer r.mu.Unlock()
	jobs := make([]*nodeCheckJob, 0, len(r.doc.Jobs))
	var pending, latest *nodeCheckJob
	for _, j := range r.doc.Jobs {
		p := j.presentation()
		if current, ok := observations[j.ID]; ok && j.Request.Kind == "node-check" {
			p.ResultState = "current-process"
			p.Results = slices.Clone(current.Results)
			p.Passed, p.Failed, p.Inconclusive, p.Skipped = current.Passed, current.Failed, current.Inconclusive, current.Skipped
		}
		if j.Request.Kind == "dns-compare" && j.State == "completed" {
			p.DNSResult = slices.Clone(r.dnsResults[j.ID])
		}
		jobs = append(jobs, p)
		latest = p
		if !j.terminal() && pending == nil {
			pending = p
		}
	}
	view["durable_jobs"] = jobs
	view["queue_blocked"] = r.blocked
	current, _ := view["job"].(*nodeCheckJob)
	if current != nil && (current.State == "running" || current.State == "canceling") {
		return
	}
	if pending != nil {
		view["job"] = pending
	} else if latest != nil && (current == nil || current.ID == latest.ID || latest.StartedAt.After(current.StartedAt)) {
		view["job"] = latest
	}
	if r.blocked {
		if current, _ := view["job"].(*nodeCheckJob); current != nil {
			copy := *current
			copy.State, copy.ErrorCode = "failed", "JOB_STORAGE_UNAVAILABLE"
			copy.Message = "Сохранённое состояние очереди не подтверждено. Новые задания приостановлены; откройте журнал. Результат запуска не выдан за сохранённый."
			view["job"] = &copy
		}
	}
}

func (a *App) cancelDurableServiceJob(ctx context.Context, id uint64) (bool, error) {
	r := &a.reconciler
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.doc.Jobs {
		j := &r.doc.Jobs[i]
		if j.ID != id {
			continue
		}
		if j.terminal() {
			return true, nil
		} // Old ID never cancels a newer worker.
		if r.blocked {
			return true, restorejournal.ErrRecovery
		}
		before := *j
		j.CancelRequested = true
		if j.State == "queued" || j.State == "interrupted" {
			finishDurableJob(j, "canceled", "canceled", time.Now())
		} else {
			j.State, j.Phase = "canceling", "cleanup"
		}
		if err := a.persistReconcilerLocked(ctx); err != nil {
			*j = before
			return true, err
		}
		if r.activeJobID == id && r.cancel != nil {
			r.cancel()
		}
		a.nodeChecks.mu.Lock()
		if a.nodeChecks.job != nil && a.nodeChecks.job.ID == id && a.nodeChecks.cancel != nil {
			a.nodeChecks.job.State, a.nodeChecks.job.Phase = "canceling", "cleanup"
			a.nodeChecks.cancel()
		}
		a.nodeChecks.mu.Unlock()
		return true, nil
	}
	return false, nil
}

// Returns true only when a queued job consumed this round. Busy admission yields
// to the existing recovery/Stop scheduler rather than retaining a waiting lease.
func (a *App) runDurableServiceJob(ctx context.Context, now time.Time) bool {
	r := &a.reconciler
	r.mu.Lock()
	if !r.started || r.blocked || ctx.Err() != nil {
		r.mu.Unlock()
		return false
	}
	stopIndex := -1
	for i, job := range r.doc.Jobs {
		if job.Request.Kind == "stop" && (job.State == "queued" || job.State == "interrupted") && !now.Before(job.NotBefore) {
			stopIndex = i
			break
		}
	}
	if stopIndex < 0 && now.Before(r.doc.ManualUntil) {
		r.mu.Unlock()
		return false
	}
	if stopIndex < 0 && r.durableBurst >= 3 {
		r.durableBurst = 0
		r.mu.Unlock()
		return false // Give due maintenance/refill tasks a bounded opportunity.
	}
	index := -1
	for i, j := range r.doc.Jobs {
		if j.Request.Kind == "node-check" && a.bulkRecoveryDueLocked(now) {
			continue
		}
		if (j.State == "queued" || j.State == "interrupted") && !now.Before(j.NotBefore) {
			index = i
			break
		}
	}
	if stopIndex >= 0 {
		index = stopIndex
	}
	if index < 0 {
		r.mu.Unlock()
		return false
	}
	j := &r.doc.Jobs[index]
	if !now.Before(j.ExpiresAt) || now.Before(j.CreatedAt.Add(-time.Minute)) || j.Attempts >= 3 {
		reason := "expired"
		if j.Attempts >= 3 {
			reason = "attempt-limit"
		}
		finishDurableJob(j, "failed", reason, now)
		_ = a.persistReconcilerLocked(ctx)
		r.mu.Unlock()
		return true
	}
	budget := 5 * time.Minute
	if isRuntimeJob(j.Request.Kind) || j.Request.Kind == "node-apply" {
		budget = defaultDataplaneApplyTimeout
	}
	if j.Request.Kind == "check" {
		budget = time.Duration(len(j.Request.ServiceIDs)+1) * time.Minute
	}
	if j.Request.Kind == "dns-compare" {
		budget = 75 * time.Second
	}
	if j.Request.Kind == "node-check" {
		budget = 75 * time.Second
	}
	j.State, j.Phase, j.CleanupOutcome = "running", "checking", "pending"
	j.Deadline = minTime(now.Add(budget), j.ExpiresAt)
	j.Attempts++
	attempt, cancel := context.WithDeadline(ctx, j.Deadline)
	r.cancel = cancel
	r.activeJobID = j.ID
	if err := a.persistReconcilerLocked(ctx); err != nil {
		cancel()
		r.cancel = nil
		r.activeJobID = 0
		r.mu.Unlock()
		return true
	}
	request := j.Request
	request.durableID, request.intentHash = j.ID, j.IntentHash
	request.durableCursor = j.Cursor
	nodeReview := j.NodeReview // Immutable copy allocated during acceptance.
	checkNetwork := j.CheckNetwork
	r.mu.Unlock()
	var err error
	var runtimeOutcome serviceRuntimeOutcome
	var dnsResult *serviceDNSCompareOutput
	var nodeBatch durableNodeCheckResult
	if isRuntimeJob(request.Kind) {
		runtimeOutcome, err = a.runDurableRuntimeJob(attempt, request)
	} else if request.Kind == "node-apply" {
		runtimeOutcome, err = a.runDurableNodeApply(attempt, request, nodeReview)
	} else if request.Kind == "dns-compare" {
		dnsResult, err = a.runDurableDNSJob(attempt, request)
	} else if request.Kind == "node-check" {
		nodeBatch, err = a.runDurableNodeCheck(attempt, request, checkNetwork)
	} else {
		var done <-chan struct{}
		done, err = a.startServiceControlJob(attempt, request, false)
		if err == nil {
			<-done
		}
	} // Includes cleanup and lease release; never detach a second owner.
	cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancel = nil
	r.activeJobID = 0
	// Enqueue may prune old terminal records while the worker was running.
	// Look up identity again rather than retaining an array index across unlock.
	j = nil
	for i := range r.doc.Jobs {
		if r.doc.Jobs[i].ID == request.durableID {
			j = &r.doc.Jobs[i]
			break
		}
	}
	if j == nil {
		r.blocked = true
		return true
	}
	j.CleanupOutcome = "joined"
	if errors.Is(err, operationgate.ErrBusy) {
		j.State, j.Phase, j.CleanupOutcome = "queued", "waiting", "not-started"
		j.Attempts--
		j.NotBefore = time.Now().Add(5 * time.Second)
	} else if a.Operations.Snapshot().Fenced {
		finishDurableJob(j, "failed", "cleanup-unverified", time.Now())
		j.CleanupOutcome = "unverified"
	} else if (isRuntimeJob(request.Kind) || request.Kind == "node-apply") && err == nil && runtimeOutcome.Code == "" {
		// A cancel can race the final commit. Successful committed state is
		// never reported as canceled (and never replayed just to obtain an ACK).
		finishDurableJob(j, "completed", "", time.Now())
	} else if j.CancelRequested {
		finishDurableJob(j, "canceled", "canceled", time.Now())
	} else if ctx.Err() != nil {
		j.State, j.Phase, j.Reason = "interrupted", "waiting", "interrupted"
	} else if err != nil {
		if request.Kind == "dns-compare" {
			_, j.DNSCode, _ = dnsCompareFailure(err)
		}
		reason := "check-failed"
		if request.Kind == "node-check" {
			reason = durableNodeCheckFailure(err)
		}
		if errors.Is(err, config.ErrRevisionChanged) {
			reason = "settings-changed"
		}
		finishDurableJob(j, "failed", reason, time.Now())
	} else if request.Kind == "dns-compare" {
		j.Cursor = 1
		finishDurableJob(j, "completed", "", time.Now())
	} else if request.Kind == "node-check" {
		j.Cursor++
		j.CheckNetwork = nodeBatch.network
		if j.Cursor < len(request.NodeIDs) {
			j.State, j.Phase = "queued", "waiting"
			j.NotBefore = time.Now().Add(time.Second)
			j.Attempts--
		} else {
			finishDurableJob(j, "completed", "", time.Now())
		}
	} else if isRuntimeJob(request.Kind) {
		j.RuntimeCode = runtimeOutcome.Code
		finishDurableJob(j, "failed", "check-failed", time.Now())
	} else if request.Kind == "node-apply" {
		j.NodeCode = runtimeOutcome.Code
		finishDurableJob(j, "failed", "check-failed", time.Now())
	} else {
		a.nodeChecks.mu.Lock()
		worker := a.nodeChecks.job
		state := "failed"
		if worker != nil && worker.ID == j.ID {
			state, j.Cursor = worker.State, worker.Completed
		}
		a.nodeChecks.mu.Unlock()
		if state == "queued" {
			j.State, j.Phase = "queued", "waiting"
			j.NotBefore = time.Now().Add(time.Second)
			j.Attempts-- // A successful bounded batch is not a failed retry.
		} else if state == "completed" {
			finishDurableJob(j, "completed", "", time.Now())
		} else if state == "canceled" {
			finishDurableJob(j, "canceled", "canceled", time.Now())
		} else {
			finishDurableJob(j, "failed", "check-failed", time.Now())
		}
	}
	persistCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	persistErr := a.persistReconcilerLocked(persistCtx)
	if persistErr == nil && j.State == "completed" && dnsResult != nil {
		if raw, e := json.Marshal(dnsResult); e == nil && len(raw) <= 64<<10 {
			if r.dnsResults == nil {
				r.dnsResults = map[uint64]json.RawMessage{}
			}
			// Keep at most four recent results; accepted job history stays intact.
			keep := map[uint64]bool{j.ID: true}
			for i := len(r.doc.Jobs) - 1; i >= 0 && len(keep) < 4; i-- {
				id := r.doc.Jobs[i].ID
				if _, ok := r.dnsResults[id]; ok {
					keep[id] = true
				}
			}
			for id := range r.dnsResults {
				if !keep[id] {
					delete(r.dnsResults, id)
				}
			}
			r.dnsResults[j.ID] = raw
		}
	}
	if !errors.Is(err, operationgate.ErrBusy) && request.Kind != "stop" {
		r.durableBurst++
	}
	return err == nil || !errors.Is(err, operationgate.ErrBusy)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (a *App) writeDurableJobFailure(w http.ResponseWriter, err error) {
	status, code, message := http.StatusServiceUnavailable, "JOB_STORAGE_UNAVAILABLE", "Очередь заданий недоступна. Проверьте журнал; новое задание не принято."
	switch {
	case errors.Is(err, operationgate.ErrBusy), errors.Is(err, operationgate.ErrRecovery):
		a.writeOperationFailure(w, err)
		return
	case errors.Is(err, errDurableKeyConflict):
		status, code, message = http.StatusConflict, "JOB_KEY_CONFLICT", "Этот запрос уже принят с другими параметрами. Обновите состояние."
	case errors.Is(err, errDurableQueueFull):
		status, code, message = http.StatusTooManyRequests, "JOB_QUEUE_FULL", "Очередь заполнена. Дождитесь завершения или отмените ненужные задания."
	case errors.Is(err, errNodeCatalogChanged):
		status, code, message = http.StatusConflict, "NODE_CATALOG_CHANGED", "Каталог изменился. Обновите его перед запуском проверки."
	case errors.Is(err, config.ErrRevisionChanged):
		status, code, message = http.StatusConflict, "SERVICE_CONTROL_CHANGED", "Настройки изменились. Обновите состояние перед проверкой."
	case errors.Is(err, errNodeJobReview):
		status, code, message = http.StatusConflict, "NODE_REVIEW_CHANGED", "Подтверждение устарело или относится к другому выбору. Откройте новый план."
	case errors.Is(err, errServiceControlRequest):
		status, code, message = http.StatusBadRequest, "JOB_REQUEST_INVALID", "Проверьте сервисы и параметры задания."
	}
	writeJSON(w, status, map[string]any{"code": code, "error": message, "not_started": true})
}
