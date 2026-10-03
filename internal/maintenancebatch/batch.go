// Package maintenancebatch coordinates a bounded sequential update batch.
// It does not own a scheduler, HTTP request, package manager or network state.
package maintenancebatch

import (
	"context"
	"errors"
	"strings"
	"time"
)

type Outcome string

const (
	Updated    Outcome = "updated_pending_activation"
	NotStarted Outcome = "not_started"
	RolledBack Outcome = "rolled_back_verified"
	Unknown    Outcome = "outcome_unknown"
)

type Item struct{ ID, Name, Package string }
type Step struct {
	Item    Item
	Outcome Outcome
	Err     error
}
type Result struct {
	Steps            []Step
	Complete         bool
	RecoveryRequired bool
	Message          string
}

// Hooks.Begin persists intent before any package mutation. Finish clears that
// intent only for a known outcome. A crash/uncertain outcome must leave Begin's
// receipt in place. Guard rechecks authority and the time window per item.
type Hooks struct {
	Guard  func(context.Context) error
	Begin  func(context.Context, Item) error
	Update func(context.Context, Item) (Outcome, error)
	Finish func(context.Context, Item, Outcome) error
}

func Run(ctx context.Context, items []Item, timeout time.Duration, h Hooks) Result {
	r := Result{Complete: true}
	if timeout <= 0 || h.Guard == nil || h.Begin == nil || h.Update == nil || h.Finish == nil {
		r.Complete = false
		r.Message = "Обслуживание не запущено: неполный безопасный обработчик."
		return r
	}
	seen := map[string]bool{}
	for _, item := range items {
		if item.ID == "" {
			r.Complete = false
			r.Message = "Обслуживание остановлено: пустой идентификатор компонента."
			return r
		}
		key := item.Package
		if key == "" {
			key = item.ID
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if err := ctx.Err(); err != nil {
			r.Complete = false
			r.Message = "Обслуживание остановлено или отменено."
			return r
		}
		if err := h.Guard(ctx); err != nil {
			r.Complete = false
			r.Message = "Обновление отложено: окно, разрешения или состояние требуют проверки."
			return r
		}
		if err := h.Begin(ctx, item); err != nil {
			r.Complete = false
			r.Message = "Обновление не запущено: намерение не сохранено или есть незавершённое обслуживание."
			return r
		}
		c, cancel := context.WithTimeout(ctx, timeout)
		outcome, err := h.Update(c, item)
		cancel()
		// A plain error is not evidence of a rollback. Reject inconsistent adapters.
		if outcome == Updated && err != nil || (outcome != Updated && outcome != NotStarted && outcome != RolledBack) {
			outcome = Unknown
		}
		r.Steps = append(r.Steps, Step{Item: item, Outcome: outcome, Err: err})
		if outcome == Unknown {
			r.Complete = false
			r.RecoveryRequired = true
			r.Message = "Обновление " + item.Name + " требует восстановления: исход или откат не подтверждён. Следующие изменения остановлены."
			return r
		}
		finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		finishErr := h.Finish(finishCtx, item, outcome)
		finishCancel()
		if finishErr != nil {
			r.Complete = false
			r.RecoveryRequired = true
			r.Message = "Итог обновления " + item.Name + " не сохранён. Следующие изменения остановлены."
			return r
		}
		if outcome != Updated {
			r.Complete = false
		}
	}
	var updated, unstarted, restored []string
	for _, s := range r.Steps {
		switch s.Outcome {
		case Updated:
			updated = append(updated, s.Item.Name)
		case NotStarted:
			unstarted = append(unstarted, s.Item.Name)
		case RolledBack:
			restored = append(restored, s.Item.Name)
		}
	}
	var notes []string
	if len(updated) > 0 {
		notes = append(notes, "Пакеты обновлены, активация runtime проверяется отдельно: "+strings.Join(updated, ", "))
	}
	if len(unstarted) > 0 {
		notes = append(notes, "Не начиналось: "+strings.Join(unstarted, ", "))
	}
	if len(restored) > 0 {
		notes = append(notes, "Откат подтверждён: "+strings.Join(restored, ", "))
	}
	if len(notes) == 0 {
		r.Message = "Каталог компонентов проверен. Обновлений нет."
	} else {
		r.Message = strings.Join(notes, ". ") + "."
	}
	return r
}

var ErrPending = errors.New("automatic component update requires recovery")
