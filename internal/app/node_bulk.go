package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const allVLESSScope = "all-vless"

func validNodeCleanupRequest(q nodeCleanupRequest) bool {
	if q.Generation == 0 {
		return false
	}
	if q.Mode == allVLESSScope {
		return len(q.NodeIDs) == 0 && q.Confirm == "DELETE_ALL_VLESS" && q.ServiceID == "" && q.NetworkProfile == "" &&
			((q.Preview && q.Review == "") || (!q.Preview && len(q.Review) == 64))
	}
	return (q.Mode == "selected" || q.Mode == "failed") && len(q.NodeIDs) >= 1 && len(q.NodeIDs) <= maxNodeCheckBatch && q.Confirm == "DELETE_NODES" && q.Review == ""
}

func validAllVLESSRequest(q nodeCheckJobRequest) bool {
	return q.Scope == allVLESSScope && q.Generation > 0 && q.Mode == "service" && q.ServiceID != "" && len(q.NodeIDs) == 0 && q.Feed == nil && q.FeedID == "" && q.Limit == 0 && q.Confirm == "CHECK_ALL_VLESS"
}

func allVLESSNodes(s nodestore.Snapshot) (ids []string, matched int) {
	ids = []string{}
	for _, n := range s.Nodes {
		if !strings.EqualFold(strings.TrimSpace(n.Protocol), "vless") {
			continue
		}
		matched++
		if !n.Disabled && n.State != "expired" {
			ids = append(ids, n.ID)
		}
	}
	sort.Strings(ids)
	return
}

// This action selects a fixed server-side catalogue snapshot. Search, country,
// source filters, page numbers and subsequently imported nodes do not alter it.
func (a *App) checkAllVLESS(w http.ResponseWriter, r *http.Request, q nodeCheckJobRequest) {
	if !validAllVLESSRequest(q) {
		writeJSON(w, 400, map[string]any{"error": "Выберите сервис и явно подтвердите проверку всего VLESS-каталога."})
		return
	}
	if a.Nodes == nil || a.NodeChecker == nil {
		writeJSON(w, 503, map[string]any{"error": "Хранилище или точная проверка недоступны."})
		return
	}
	release, err := a.Operations.Exclusive(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
	if err != nil {
		writeNodeError(w, err)
		return
	}
	if snapshot.Generation != q.Generation {
		writeJSON(w, 409, map[string]any{"error": "Каталог изменился. Обновите его перед запуском.", "not_started": true})
		return
	}
	var service catalog.Service
	for _, s := range a.catalogSnapshot().Services {
		if s.ID == q.ServiceID && serviceHasNodeProbe(s) {
			service = s
			break
		}
	}
	if service.ID == "" {
		writeJSON(w, 400, map[string]any{"error": "У сервиса нет доступной проверки."})
		return
	}
	// Detach slices in the definition from later catalogue updates.
	raw, err := json.Marshal(service)
	var frozen catalog.Service
	if err != nil || json.Unmarshal(raw, &frozen) != nil {
		writeJSON(w, 503, map[string]any{"error": "Не удалось сохранить состав сервиса."})
		return
	}
	if a.Store != nil && a.Store.Get().ServiceControl.Stopped {
		writeJSON(w, 409, map[string]any{"error": "Маршруты остановлены пользователем. Массовая проверка не запущена.", "not_started": true})
		return
	}
	service = frozen
	ids, matched := allVLESSNodes(snapshot)
	if len(ids) == 0 {
		writeJSON(w, 400, map[string]any{"error": "Нет VLESS для проверки. Отключённые и истёкшие записи пропускаются.", "not_started": true})
		return
	}
	profile, err := a.freshNetworkProfile(r.Context())
	if err != nil || profile == "" {
		writeNodeNetworkError(w)
		return
	}
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.closed || a.nodeChecks.root == nil || a.nodeChecks.root.Err() != nil {
		a.nodeChecks.mu.Unlock()
		writeJSON(w, 503, map[string]any{"error": "Приложение завершает работу."})
		return
	}
	if a.nodeChecks.cancel != nil {
		a.nodeChecks.mu.Unlock()
		writeJSON(w, 409, map[string]any{"error": "Уже выполняется проверка. Остановите её или дождитесь завершения.", "not_started": true})
		return
	}
	budget := min(time.Duration(len(ids)+1)*time.Minute, 12*time.Hour)
	ctx, cancel := context.WithTimeout(a.nodeChecks.root, budget)
	a.nodeChecks.nextID++
	id := a.nodeChecks.nextID
	a.nodeChecks.job = &nodeCheckJob{ID: id, Scope: allVLESSScope, Matched: matched, Mode: "service", ServiceID: service.ID, State: "running", Phase: "waiting", Total: len(ids), Skipped: matched - len(ids), StartedAt: time.Now().UTC(), Message: "Очередь всего VLESS-каталога создана. Маршруты не применяются.", Results: []nodeCheckItem{}}
	done := make(chan struct{})
	a.nodeChecks.done = done
	a.nodeChecks.cancel = cancel
	a.nodeChecks.mu.Unlock()
	go a.runAllVLESS(ctx, cancel, done, id, ids, service, profile)
	writeJSON(w, 202, a.nodeCheckSnapshot())
}

func (a *App) bulkWait(ctx context.Context, delay time.Duration) error {
	if a.nodeChecks.bulkWait != nil {
		return a.nodeChecks.bulkWait(ctx, delay)
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Recovery keeps priority at node boundaries. Never release another operation's
// gate or bypass cleanup. Busy admission is retried; fencing is a hard stop.
func (a *App) bulkRecoveryDue(now time.Time) bool {
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	r := &a.reconciler
	if !r.started || r.blocked {
		return false
	}
	if now.Before(r.doc.ManualUntil) {
		return true
	}
	for _, kind := range []string{"node-recovery", "node-fallback", "feeds"} {
		found := false
		for _, op := range r.doc.Operations {
			if op.Kind != kind {
				continue
			}
			found = true
			if op.State == "running" || !now.Before(op.NextRun) {
				return true
			}
			break
		}
		// reconcileRound dispatches missing operations on its first round.
		// Even disabled features receive a completed record and next-run time,
		// so waiting here cannot reserve priority for a nonexistent operation.
		if !found {
			return true
		}
	}
	return false
}
func (a *App) bulkAdmission(ctx context.Context) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !a.bulkRecoveryDue(time.Now()) {
			release, err := a.Operations.Exclusive(ctx)
			if err == nil {
				return release, nil
			}
			if !errors.Is(err, operationgate.ErrBusy) {
				return nil, err
			}
		}
		if err := a.bulkWait(ctx, time.Second); err != nil {
			return nil, err
		}
	}
}

func (a *App) bulkMessage(id uint64, phase, message string) {
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	if j := a.nodeChecks.job; j != nil && j.ID == id && j.State != "canceling" {
		j.Phase = phase
		j.Message = message
	}
}

func (a *App) runAllVLESS(ctx context.Context, cancel context.CancelFunc, done chan struct{}, jobID uint64, ids []string, service catalog.Service, profile string) {
	defer close(done)
	defer cancel()
	a.runServiceNodeQueue(ctx, jobID, ids, service, profile, true)
}

// Both selected nodes and the full catalogue share the same recovery priority
// and cleanup boundary. Each iteration owns its admission until cleanup ends.
func (a *App) runServiceNodeQueue(ctx context.Context, jobID uint64, ids []string, service catalog.Service, profile string, vlessOnly bool) {
	code, message := "", "Проверка подключений завершена. Маршруты не применялись."
	definition := applyReviewHash(service)
	for index, id := range ids {
		a.bulkMessage(jobID, "waiting", "Ожидаем ресурс роутера. Восстановление маршрутов имеет приоритет между узлами.")
		release, err := a.bulkAdmission(ctx)
		if err != nil {
			code, message = "BULK_ADMISSION_STOPPED", "Проверка остановлена: ресурс или восстановление недоступны."
			break
		}
		// All checks and their bounded cleanup complete before this lease is released.
		var item nodeCheckItem
		skipped := false
		stopCode, stopMessage := "", ""
		func() {
			defer release()
			if !a.nodeCheckDefinitionCurrent(service.ID, definition) {
				stopCode, stopMessage = "BULK_SERVICE_CHANGED", "Состав сервиса изменился. Запустите новую проверку."
				return
			}
			if a.Store != nil && a.Store.Get().ServiceControl.Stopped {
				stopCode, stopMessage = "BULK_USER_STOPPED", "Маршруты остановлены пользователем. Очередь прекращена."
				return
			}
			current, e := a.freshNetworkProfile(ctx)
			if e != nil || current != profile {
				stopCode, stopMessage = "BULK_NETWORK_CHANGED", "Сеть изменилась или не подтверждена. Остаток очереди не проверялся."
				return
			}
			s, e := a.Nodes.Snapshot(ctx, time.Now())
			if e != nil {
				stopCode, stopMessage = "BULK_STORE_UNAVAILABLE", "Каталог недоступен. Очередь остановлена."
				return
			}
			eligible := false
			for _, n := range s.Nodes {
				if n.ID == id && (!vlessOnly || strings.EqualFold(strings.TrimSpace(n.Protocol), "vless")) && !n.Disabled && n.State != "expired" {
					eligible = true
					break
				}
			}
			if !eligible {
				item = nodeCheckItem{NodeID: id, NetworkProfile: profile, CheckedAt: time.Now().UTC(), ErrorCode: "bulk-node-skipped", Message: "Запись удалена, отключена или истёк срок. Пропущена."}
				skipped = true
				return
			}
			a.bulkMessage(jobID, "checking", "Проверяем подключение: протокол, точный выход и выбранный сервис.")
			item = a.runNodeCheckItem(ctx, "service", id, service, profile, nil)
			if item.ErrorCode == "node-cleanup-failed" {
				// A failed cleanup takes precedence over canceled/stale proof.
				// Preserve it so the user sees why further checks are blocked.
				return
			}
			if !a.nodeCheckDefinitionCurrent(service.ID, definition) {
				stopCode, stopMessage = "BULK_SERVICE_CHANGED", "Состав сервиса изменился во время проверки."
				return
			}
			current, e = a.freshNetworkProfile(ctx)
			if e != nil || current != profile {
				stopCode, stopMessage = "BULK_NETWORK_CHANGED", "Сеть изменилась. Результат не выдан за актуальный."
				return
			}
		}()
		if stopCode != "" {
			code, message = stopCode, stopMessage
			break
		}
		if ctx.Err() != nil && item.ErrorCode != "node-cleanup-failed" {
			break
		}
		a.nodeChecks.mu.Lock()
		if j := a.nodeChecks.job; j != nil && j.ID == jobID {
			j.Results = append(j.Results, item)
			if len(j.Results) > maxNodeCheckBatch {
				j.Results = append([]nodeCheckItem(nil), j.Results[len(j.Results)-maxNodeCheckBatch:]...)
			}
			j.Completed++
			switch {
			case skipped:
				j.Skipped++
			case item.Available && item.Verdict == "PASS" && item.TestLevel == "service":
				j.Passed++
			case item.Verdict == "BLOCKED" || item.Verdict == "MISROUTED" || item.Verdict == "FAIL":
				j.Failed++
			default:
				j.Inconclusive++
			}
		}
		a.nodeChecks.mu.Unlock()
		if item.ErrorCode == "node-cleanup-failed" {
			code, message = "BULK_CLEANUP_REQUIRED", "Очистка checker не подтверждена. Новые проверки остановлены; требуется восстановление."
			break
		}
		// Give queued router work an opportunity without reserving the global gate.
		if index+1 < len(ids) {
			if err := a.bulkWait(ctx, time.Second); err != nil {
				break
			}
		}
	}
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	if j := a.nodeChecks.job; j != nil && j.ID == jobID {
		finished := time.Now().UTC()
		j.FinishedAt = &finished
		j.Phase = "finished"
		j.State = "completed"
		j.Message = message
		j.ErrorCode = code
		if code == "BULK_CLEANUP_REQUIRED" {
			j.State = "failed"
		} else if ctx.Err() != nil {
			j.State = "canceled"
			j.Message = "Очередь остановлена. Завершённые результаты сохранены."
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				j.ErrorCode = "BULK_DEADLINE"
				j.Message = "Исчерпан бюджет очереди. Завершённые результаты сохранены; остаток не проверялся."
			}
		} else if code != "" {
			j.State = "failed"
		}
		a.nodeChecks.cancel = nil
	}
}
