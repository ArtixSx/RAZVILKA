package app

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

// One source or an explicit set of node IDs, never both. New fetch workflows
// require consent; the unchanged per-node request remains backward compatible.
func validNodeCheckJobRequest(r nodeCheckJobRequest) bool {
	if r.Mode != "tcp" && r.Mode != "service" {
		return false
	}
	if r.Feed != nil || r.FeedID != "" {
		return r.Mode == "service" && r.ServiceID != "" && len(r.NodeIDs) == 0 &&
			!(r.Feed != nil && r.FeedID != "") && r.Confirm == "FETCH_AND_CHECK_NODES" && r.Limit >= 0 && r.Limit <= maxNodeCheckBatch &&
			(r.Feed == nil || r.Feed.Limit >= 0 && r.Feed.Limit <= maxNodeCheckBatch)
	}
	return r.Confirm == "" && r.Limit == 0 && len(r.NodeIDs) > 0 && len(r.NodeIDs) <= maxNodeCheckBatch
}

func (a *App) validateNodeCheckFeed(r nodeCheckJobRequest) (int, error) {
	if r.Feed == nil && r.FeedID == "" {
		return 0, nil
	}
	if a.NodeFeeds == nil {
		return 0, providerfeed.ErrStore
	}
	if r.Feed != nil {
		if err := providerfeed.ValidateRequest(*r.Feed); err != nil {
			return 0, err
		}
		if r.Feed.Limit == 0 {
			return 32, nil
		}
		return r.Feed.Limit, nil
	}
	saved, err := a.NodeFeeds.Saved(r.FeedID)
	if err != nil {
		return 0, err
	}
	limit := r.Limit
	if limit == 0 {
		limit = 32
	}
	return min(limit, max(1, saved.Limit)), nil
}

func (a *App) nodeCheckDefinitionCurrent(id, expected string) bool {
	for _, s := range a.catalogSnapshot().Services {
		if s.ID == id {
			return applyReviewHash(s) == expected
		}
	}
	return false
}

// Called without application admission. The existing importer owns short store
// leases, leaving the bounded download outside the gate. The snapshot phase
// takes a fresh lease, yielding to recovery before the first engine check.
func (a *App) fetchNodeCheckCandidates(ctx context.Context, jobID uint64, request nodeCheckJobRequest) ([]string, error) {
	var result providerfeed.Result
	var err error
	if a.nodeChecks.fetchSource != nil {
		result, err = a.nodeChecks.fetchSource(ctx, request)
	} else if request.Feed != nil {
		result, err = a.NodeFeeds.SyncWithAdmission(ctx, *request.Feed, a.Operations.Enter)
	} else {
		result, err = a.NodeFeeds.SyncSavedWithAdmission(ctx, request.FeedID, a.Operations.Enter)
	}
	result.Issues = nil
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	var ids []string
	skipped := 0
	if err == nil {
		var release func()
		release, err = a.bulkAdmission(ctx)
		if err == nil {
			defer release()
		}
	}
	if err == nil {
		var snapshot nodestore.Snapshot
		snapshot, err = a.Nodes.Snapshot(ctx, time.Now())
		if err == nil {
			limit := request.Limit
			if limit == 0 {
				limit = 32
			}
			if request.Feed != nil {
				limit = request.Feed.Limit
				if limit == 0 {
					limit = 32
				}
			}
			ids, skipped = fetchedCheckNodeIDs(result, snapshot, limit)
		}
	}
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	if a.nodeChecks.job == nil || a.nodeChecks.job.ID != jobID {
		return nil, context.Canceled
	}
	job := a.nodeChecks.job
	job.Fetch = &result
	job.Skipped = skipped
	job.Phase = "checking"
	job.Total = len(ids)
	job.Message = "Источник получен. Проверяем протокол, точный выход и веб-сценарий выбранного сервиса."
	if err != nil {
		job.ErrorCode = providerfeed.ErrorCode(err)
		job.Message = nodeFetchCheckError(err)
	} else if len(ids) == 0 {
		job.Message = "Пригодных для запуска проверки узлов в выборке нет. Маршруты и прежние записи сохранены."
	}
	return ids, err
}

// A paged 304 names the next exact batch. Only legacy imports without snapshot
// metadata fall back to still-valid cached members of this source.
func fetchedCheckNodeIDs(result providerfeed.Result, snapshot nodestore.Snapshot, limit int) ([]string, int) {
	wanted := map[string]bool{}
	for _, id := range result.NodeIDs {
		wanted[id] = true
	}
	ids := []string{}
	skipped := 0
	for _, node := range snapshot.Nodes {
		match := wanted[node.ID]
		if result.NotModified && result.SnapshotEntries == 0 {
			match = false
			for _, origin := range node.Origins {
				if origin.SourceID == result.SourceID && origin.ExpiresAt.After(time.Now()) && !origin.ReceivedAt.After(time.Now()) {
					match = true
					break
				}
			}
		}
		if !match {
			continue
		}
		if node.Disabled || node.State == "expired" || len(ids) >= limit {
			skipped++
			continue
		}
		ids = append(ids, node.ID)
	}
	return ids, skipped
}

func nodeFetchCheckError(err error) string {
	switch {
	case errors.Is(err, providerfeed.ErrPartial):
		return "В источнике есть отклонённые строки. Просмотрите источник и разрешите частичный импорт отдельно; проверки не запускались."
	case errors.Is(err, providerfeed.ErrCapacity):
		return "Каталог узлов заполнен. Удалите ненужные неиспользуемые записи; рабочие маршруты сохранены."
	case errors.Is(err, providerfeed.ErrSize):
		return "Источник превышает лимит загрузки. Выберите меньший срез подписки."
	case errors.Is(err, providerfeed.ErrBusy):
		return "Источник занят другой загрузкой. Повторите после её завершения."
	default:
		return "Источник не получен или импорт не подтверждён. Прежние узлы и маршруты сохранены; сетевые проверки не запускались."
	}
}
