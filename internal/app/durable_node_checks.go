package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type nodeCatalogCheckSpec struct {
	Generation      uint64 `json:"generation"`
	Matched         int    `json:"matched"`
	SelectionDigest string `json:"selection_digest,omitempty"`
}

var errNodeCatalogChanged = errors.New("node catalogue changed before acceptance")

// Catalogue references are resolved exactly once at admission. Retries compare
// the original selector, not health updates or later additions to the catalogue.
func durableRequestFingerprint(r serviceControlJobRequest) string {
	if r.Kind == "node-check" && r.NodeCatalog != nil {
		r.NodeIDs = nil
		selector := &nodeCatalogCheckSpec{Generation: r.NodeCatalog.Generation, SelectionDigest: r.NodeCatalog.SelectionDigest}
		if selector.SelectionDigest != "" {
			selector.Generation = 0
		}
		r.NodeCatalog = selector
	}
	return applyReviewHash(r)
}

func durableJobTotal(r serviceControlJobRequest) int {
	if r.Kind == "node-check" {
		return len(r.NodeIDs)
	}
	return len(r.ServiceIDs)
}

// Only frozen references enter the existing reconciler. Source URLs, node
// credentials and previously successful results are never replayable jobs.
func validDurableNodeCheck(r serviceControlJobRequest) bool {
	limit := maxNodeCheckBatch
	if r.NodeCatalog != nil {
		limit = nodestore.MaxNodes
		if r.NodeCheckMode != "service" || r.NodeCatalog.Generation == 0 || r.NodeCatalog.SelectionDigest != "" && !validJobHash(r.NodeCatalog.SelectionDigest) {
			return false
		}
		if r.resolveNodeCatalog {
			if len(r.NodeIDs) != 0 || r.NodeCatalog.Matched != 0 {
				return false
			}
		} else if r.NodeCatalog.Matched < len(r.NodeIDs) || r.NodeCatalog.Matched > limit {
			return false
		}
	} else if r.resolveNodeCatalog {
		return false
	}
	if r.ExpectedRevision == nil || r.NodeApply != nil || r.DNS != nil || (len(r.NodeIDs) == 0 && !r.resolveNodeCatalog) || len(r.NodeIDs) > limit {
		return false
	}
	if r.NodeCheckMode == "service" {
		if len(r.ServiceIDs) != 1 || len(r.ServiceIDs[0]) == 0 || len(r.ServiceIDs[0]) > 128 || strings.Trim(r.ServiceIDs[0], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != "" {
			return false
		}
	} else if r.NodeCheckMode != "tcp" || len(r.ServiceIDs) != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range r.NodeIDs {
		if !strings.HasPrefix(id, "node-") || !validJobHash(strings.TrimPrefix(id, "node-")) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func (a *App) validateDurableNodeCheckSelection(ctx context.Context, r *serviceControlJobRequest, services []catalog.Service) error {
	if a.Nodes == nil || r.NodeCheckMode == "service" && (a.NodeChecker == nil || len(services) != 1 || !serviceHasNodeProbe(services[0])) {
		return errServiceControlRequest
	}
	if a.Store.Get().ServiceControl.Stopped {
		return config.ErrRevisionChanged
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return err
	}
	if r.resolveNodeCatalog {
		if !matchesNodeCheckCatalog(snapshot, r.NodeCatalog.Generation, r.NodeCatalog.SelectionDigest) {
			return errNodeCatalogChanged
		}
		r.NodeIDs, r.NodeCatalog.Matched = allVLESSNodes(snapshot)
		r.resolveNodeCatalog = false
		if !validDurableNodeCheck(*r) {
			return errServiceControlRequest
		}
	}
	eligible := map[string]bool{}
	for _, node := range snapshot.Nodes {
		eligible[node.ID] = !node.Disabled && node.State != "expired"
	}
	for _, id := range r.NodeIDs {
		if !eligible[id] {
			return errServiceControlRequest
		}
	}
	return nil
}

// Enqueue only freezes read-only intent. It must not compete with a running
// service probe for network admission. The existing worker acquires the lease
// and revalidates all references/revision/definitions before its first IO.
func (a *App) prepareDurableNodeCheck(ctx context.Context, request *serviceControlJobRequest) (string, error) {
	if a.Store == nil {
		return "", errServiceControlRequest
	}
	if a.Operations.Snapshot().Fenced {
		return "", operationgate.ErrRecovery
	}
	if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
		return "", operationgate.ErrBusy
	}
	cfg := a.Store.Get()
	if cfg.Revision != *request.ExpectedRevision {
		return "", config.ErrRevisionChanged
	}
	services := []catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		if len(request.ServiceIDs) == 1 && service.ID == request.ServiceIDs[0] {
			services = append(services, service)
			break
		}
	}
	if len(services) != len(request.ServiceIDs) {
		return "", errServiceControlRequest
	}
	if err := a.validateDurableNodeCheckSelection(ctx, request, services); err != nil {
		return "", err
	}
	intent := durableServiceIntentHash(cfg, services)
	if current := a.Store.Get(); current.Revision != cfg.Revision || durableServiceIntentHash(current, services) != intent || len(services) == 1 && !a.nodeCheckDefinitionCurrent(services[0].ID, applyReviewHash(services[0])) {
		return "", config.ErrRevisionChanged
	}
	if a.Operations.Snapshot().Fenced {
		return "", operationgate.ErrRecovery
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return intent, nil
}

func (a *App) acceptDurableNodeChecks(w http.ResponseWriter, r *http.Request, q nodeCheckJobRequest) {
	request := serviceControlJobRequest{Kind: "node-check", NodeCheckMode: q.Mode, NodeIDs: q.NodeIDs, ExpectedRevision: q.ExpectedRevision, IdempotencyKey: q.IdempotencyKey}
	if q.Scope == allVLESSScope {
		request.NodeCatalog = &nodeCatalogCheckSpec{Generation: q.Generation, SelectionDigest: q.CatalogDigest}
		request.resolveNodeCatalog = true
	}
	if q.Mode == "service" {
		request.ServiceIDs = []string{q.ServiceID}
	}
	job, err := a.enqueueDurableServiceJob(r.Context(), request)
	if err != nil {
		a.writeDurableJobFailure(w, err)
		return
	}
	view := a.nodeCheckCurrentView()
	view["job"] = job.presentation()
	writeJSON(w, http.StatusAccepted, view)
}

func (a *App) nodeCheckCurrentView() map[string]any {
	view := a.nodeCheckSnapshot()
	a.addDurableServiceJobs(view)
	view["durable_selected_checks"] = true
	view["durable_all_vless"] = true
	return view
}

type durableNodeCheckResult struct{ network string }

func durableNodeCheckFailure(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "check-timeout"
	case errors.Is(err, dataplane.ErrExactNodeNetworkChanged):
		return "network-unconfirmed"
	case errors.Is(err, config.ErrRevisionChanged), errors.Is(err, dataplane.ErrReviewChanged):
		return "settings-changed"
	case errors.Is(err, nodestore.ErrStore), errors.Is(err, nodestore.ErrRecovery):
		return "node-store-unavailable"
	case errors.Is(err, context.Canceled):
		return "interrupted"
	default:
		return "check-failed"
	}
}

func durableNodeCheckFailureMessage(reason string) string {
	switch reason {
	case "network-unconfirmed":
		return "Проверка остановлена: прежнее состояние сети больше не подтверждено. Результаты относятся к прежней сети; запустите новую проверку."
	case "check-timeout":
		return "Проверка остановлена по таймауту. Временные ресурсы освобождены; оставшиеся подключения не проверены."
	case "node-store-unavailable":
		return "Проверка остановлена: не удалось прочитать хранилище подключений. Откройте журнал и проверьте накопитель."
	case "settings-changed":
		return "Проверка остановлена: изменились настройки или определение сервиса. Запустите новую проверку."
	case "cleanup-unverified":
		return "Очистка временного подключения не подтверждена. Новые сетевые действия заблокированы; откройте журнал."
	}
	return "Проверка не завершена. Оставшиеся подключения не проверены; рабочие маршруты не изменены."
}

// One node per reconciler turn: route recovery and Stop get the next turn.
// The lease stays owned until the checker has joined all temporary cleanup.
func (a *App) runDurableNodeCheck(ctx context.Context, r serviceControlJobRequest, network string) (out durableNodeCheckResult, err error) {
	if !validDurableNodeCheck(r) || r.durableCursor < 0 || r.durableCursor >= len(r.NodeIDs) || a.Store == nil || a.Nodes == nil {
		return out, errServiceControlRequest
	}
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return out, err
	}
	var done chan struct{}
	defer func() {
		release()
		if done != nil {
			close(done)
		}
	}()
	services := []catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		if len(r.ServiceIDs) == 1 && service.ID == r.ServiceIDs[0] {
			services = append(services, service)
			break
		}
	}
	cfg := a.Store.Get()
	if cfg.Revision != *r.ExpectedRevision || cfg.ServiceControl.Stopped || r.intentHash != durableServiceIntentHash(cfg, services) {
		return out, config.ErrRevisionChanged
	}
	if r.NodeCheckMode == "service" && (a.NodeChecker == nil || len(services) != 1 || !serviceHasNodeProbe(services[0])) {
		return out, errServiceControlRequest
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil || profile == "" {
		return out, dataplane.ErrExactNodeNetworkChanged
	}
	out.network = applyReviewHash(profile)
	if network != "" && network != out.network {
		return out, dataplane.ErrExactNodeNetworkChanged
	}
	checkCtx, cancel := context.WithCancel(ctx)
	done = make(chan struct{})
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.closed || a.nodeChecks.root == nil || a.nodeChecks.root.Err() != nil || ctx.Err() != nil {
		a.nodeChecks.mu.Unlock()
		cancel()
		return out, context.Canceled
	}
	if a.nodeChecks.cancel != nil {
		a.nodeChecks.mu.Unlock()
		cancel()
		return out, operationgate.ErrBusy
	}
	job := a.nodeChecks.job
	if job == nil || job.ID != r.durableID {
		job = a.nodeChecks.batchResults[r.durableID]
	}
	if job == nil {
		job = &nodeCheckJob{ID: r.durableID, Mode: r.NodeCheckMode, Total: len(r.NodeIDs), StartedAt: time.Now().UTC(), Results: []nodeCheckItem{}}
		if len(r.ServiceIDs) == 1 {
			job.ServiceID = r.ServiceIDs[0]
		}
		if r.NodeCatalog != nil {
			job.Scope, job.Matched, job.Skipped = allVLESSScope, r.NodeCatalog.Matched, r.NodeCatalog.Matched-len(r.NodeIDs)
		}
	}
	a.nodeChecks.job = job
	job.Completed, job.State, job.Phase, job.FinishedAt = r.durableCursor, "running", "checking", nil
	job.Message = "Проверяем подключение. Между узлами очередь уступает восстановлению маршрутов."
	a.nodeChecks.cancel, a.nodeChecks.done = cancel, done
	a.nodeChecks.mu.Unlock()
	defer func() {
		cancel()
		a.nodeChecks.mu.Lock()
		if job := a.nodeChecks.job; job != nil && job.ID == r.durableID {
			job.State, job.Phase = "queued", "waiting"
			if err != nil {
				job.State, job.Message = "failed", nodeCheckFailureMessage(err)
			}
			a.nodeChecks.cancel = nil
		}
		a.nodeChecks.mu.Unlock()
	}()
	id := r.NodeIDs[r.durableCursor]
	snapshot, err := a.Nodes.Snapshot(checkCtx, time.Now())
	if err != nil {
		return out, err
	}
	eligible := false
	for _, node := range snapshot.Nodes {
		if node.ID == id && !node.Disabled && node.State != "expired" && (r.NodeCatalog == nil || strings.EqualFold(strings.TrimSpace(node.Protocol), "vless")) {
			eligible = true
			break
		}
	}
	item := nodeCheckItem{NodeID: id, CheckedAt: time.Now().UTC(), NetworkProfile: profile, ErrorCode: "bulk-node-skipped", Message: "Подключение удалено, отключено или истекло. Пропущено."}
	if eligible {
		var service catalog.Service
		if len(services) == 1 {
			service = services[0]
		}
		pinger := a.NodePinger
		if pinger == nil {
			pinger = dataplane.NewTCPNodePinger()
		}
		item = a.runNodeCheckItem(checkCtx, r.NodeCheckMode, id, service, profile, pinger)
		if item.ErrorCode == "node-cleanup-failed" {
			a.Operations.Fence()
			return out, operationgate.ErrRecovery
		}
	}
	if checkCtx.Err() != nil {
		return out, checkCtx.Err()
	}
	if current, e := a.freshNetworkProfile(checkCtx); e != nil || current != profile {
		return out, dataplane.ErrExactNodeNetworkChanged
	}
	if r.intentHash != durableServiceIntentHash(a.Store.Get(), services) || len(services) == 1 && !a.nodeCheckDefinitionCurrent(services[0].ID, applyReviewHash(services[0])) {
		return out, config.ErrRevisionChanged
	}
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	if job := a.nodeChecks.job; job != nil && job.ID == r.durableID {
		job.Results = append(slices.Clone(job.Results), item)
		if len(job.Results) > maxNodeCheckBatch {
			job.Results = slices.Clone(job.Results[len(job.Results)-maxNodeCheckBatch:])
		}
		job.Completed++
		switch {
		case !eligible:
			job.Skipped++
		case item.Available && item.Verdict == "PASS" && item.TestLevel == "service":
			job.Passed++
		case slices.Contains([]string{"BLOCKED", "MISROUTED", "FAIL"}, item.Verdict):
			job.Failed++
		default:
			job.Inconclusive++
		}
		if a.nodeChecks.batchResults == nil {
			a.nodeChecks.batchResults = map[uint64]*nodeCheckJob{}
		}
		a.nodeChecks.batchResults[job.ID] = job
		if len(a.nodeChecks.batchResults) > 4 {
			var oldest *nodeCheckJob
			for id, candidate := range a.nodeChecks.batchResults {
				if id != job.ID && (oldest == nil || candidate.StartedAt.Before(oldest.StartedAt)) {
					oldest = candidate
				}
			}
			delete(a.nodeChecks.batchResults, oldest.ID)
		}
		if r.NodeCheckMode == "tcp" {
			if a.nodeChecks.pings == nil {
				a.nodeChecks.pings = map[string]nodeCheckItem{}
			}
			if len(a.nodeChecks.pings) >= maxNodeCheckBatch && a.nodeChecks.pings[id].NodeID == "" {
				oldest := ""
				for key, value := range a.nodeChecks.pings {
					if oldest == "" || value.CheckedAt.Before(a.nodeChecks.pings[oldest].CheckedAt) {
						oldest = key
					}
				}
				delete(a.nodeChecks.pings, oldest)
			}
			a.nodeChecks.pings[id] = item
		}
	}
	return out, nil
}

func (a *App) nodeBatchMemoryResults() map[uint64]nodeCheckJob {
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	results := make(map[uint64]nodeCheckJob, len(a.nodeChecks.batchResults))
	for id, job := range a.nodeChecks.batchResults {
		copy := *job
		copy.Results = slices.Clone(job.Results)
		results[id] = copy
	}
	return results
}
