package app

import (
	"context"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Retry data is process-local: retrying read/check/prepare after a restart is
// safe. Only successfully fulfilled windows are persisted in the existing
// schema. This does not grant permission for registration or package installation.
type maintenanceAttempt struct {
	Key      string
	Next     time.Time
	Attempts int
	Running  bool
	Pending  bool
}

// Caller holds the common exclusive operation admission. This is dispatched
// before ordinary service work, not only when the service queue happens to empty.
func (a *App) autonomyMaintenance(ctx context.Context, p autonomy.Policy, now time.Time) {
	for _, task := range []struct {
		name   string
		window autonomy.Window
	}{{"application", p.Application}, {"components", p.Components}} {
		slot, open := autonomy.WindowKey(task.window, p.Timezone, now)
		if !open || ctx.Err() != nil {
			continue
		}
		key := slot + ":" + task.window.Mode
		channel := updatecheck.NormalizedChannel(p.UpdateChannel)
		if task.name == "application" && channel != "stable" {
			key += ":" + channel
		}
		a.autonomy.mu.Lock()
		if a.autonomy.blocked || !reflect.DeepEqual(a.autonomy.doc.Policy, p) {
			a.autonomy.mu.Unlock()
			return
		}
		completed := a.autonomy.doc.Maintenance[task.name]
		// Preserve legacy receipts, whose value consisted only of the slot.
		if completed == key || completed == slot && (task.name != "application" || channel == "stable") {
			a.autonomy.mu.Unlock()
			continue
		}
		if a.autonomy.maintenanceAttempts == nil {
			a.autonomy.maintenanceAttempts = map[string]maintenanceAttempt{}
		}
		previous := a.autonomy.maintenanceAttempts[task.name]
		if previous.Key != key {
			previous = maintenanceAttempt{Key: key}
		}
		if previous.Running || previous.Attempts >= 3 && !previous.Pending || now.Before(previous.Next) {
			a.autonomy.mu.Unlock()
			continue
		}
		if !previous.Pending {
			previous.Attempts++
		}
		previous.Running = true
		a.autonomy.maintenanceAttempts[task.name] = previous
		a.autonomy.mu.Unlock()

		done, pending, message := a.runMaintenanceCheck(ctx, task.name, task.window, previous.Pending)
		a.autonomy.mu.Lock()
		previous.Running = false
		previous.Pending = pending
		previous.Next = now.Add(time.Duration(1<<min(previous.Attempts-1, 2)) * time.Minute)
		a.autonomy.maintenanceAttempts[task.name] = previous
		if ctx.Err() != nil || a.autonomy.blocked || !reflect.DeepEqual(a.autonomy.doc.Policy, p) {
			a.autonomy.mu.Unlock()
			return
		}
		if done {
			old := a.autonomy.doc.Maintenance[task.name]
			a.autonomy.doc.Maintenance[task.name] = key
			if err := a.persistAutonomyLocked(ctx); err != nil {
				if old == "" {
					delete(a.autonomy.doc.Maintenance, task.name)
				} else {
					a.autonomy.doc.Maintenance[task.name] = old
				}
				message = "Итог обслуживания не удалось сохранить. Проверьте хранилище автоматики."
			}
		} else if pending {
			message += " Статус существующей подготовки будет проверен повторно; новая задача не создаётся."
		} else if previous.Attempts < 3 {
			message += " Повтор с паузой, только в открытом окне обслуживания."
		} else {
			message += " Лимит повторов этого окна исчерпан; следующий запуск в новом окне."
		}
		a.autonomy.maintenanceMessage = message
		a.autonomy.mu.Unlock()
	}
}

func (a *App) runMaintenanceCheck(ctx context.Context, name string, w autonomy.Window, wasPending bool) (bool, bool, string) {
	if a.autonomy.maintenanceTestRun != nil {
		return a.autonomy.maintenanceTestRun(ctx, name, w, wasPending)
	}
	if name == "components" {
		if a.Components == nil {
			return false, false, "Менеджер компонентов недоступен."
		}
		check, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		views, err := a.Components.List(check, true)
		if err != nil {
			return false, false, "Каталог компонентов не проверен. Установленные версии не изменены."
		}
		for _, view := range views {
			if view.State == "check-failed" || view.State == "installed-check-failed" {
				return false, false, "Источник части компонентов недоступен. Существующие версии сохранены; проверка будет повторена."
			}
		}
		return true, false, "Каталог компонентов проверен. Автоматическая установка не включена."
	}
	if w.Mode == "prepare" {
		if a.SelfUpdate == nil || a.Store == nil {
			return false, false, "Подготовка обновления недоступна."
		}
		current := a.SelfUpdate.Snapshot()
		switch current.State {
		case "ready":
			fresh := !current.UpdatedAt.IsZero() && !current.UpdatedAt.After(time.Now()) && time.Since(current.UpdatedAt) < 15*time.Minute
			if fresh && current.ConfigRevision == a.Store.Get().Revision && updatecheck.NormalizedChannel(current.Channel) == updatecheck.NormalizedChannel(a.autonomyPolicy().UpdateChannel) {
				return true, false, "Архив подготовлен для текущей редакции и канала. Установка автоматически не запускается."
			}
			// The owned old job may be replaced by Prepare, never installed with
			// stale policy/age merely because yesterday's download was ready.

		case "preparing":
			return false, true, "Подготовка архива ещё выполняется."
		case "installing", "restarting", "requires-review":
			return false, false, "Установщик занят или требует восстановления."
		}
		if wasPending {
			return false, false, "Предыдущая подготовка не завершилась успешно. Повтор возможен отдельной ограниченной попыткой."
		}
		if a.Updates == nil {
			return false, false, "Проверка канала обновлений недоступна."
		}
		check, cancel := context.WithTimeout(ctx, 30*time.Second)
		latest := a.Updates.CheckChannel(check, true, a.autonomyPolicy().UpdateChannel)
		cancel()
		if latest.State == "check-failed" || latest.MetadataStale {
			return false, false, "Каталог выпусков не подтверждён. Загрузка отложена."
		}
		if !latest.CanPrepare {
			return true, false, "Новой подходящей версии в выбранном канале нет. Архив повторно не загружался."
		}
		cfg := a.Store.Get()
		job, err := a.SelfUpdate.PrepareChannel(cfg.Revision, updatecheck.ConfigFingerprint(cfg), a.autonomyPolicy().UpdateChannel)
		if err != nil {
			return false, false, "Подготовка отложена: установщик занят или условия не выполнены."
		}
		// Acceptance is not completion. Re-observe the existing job on a later round;
		// do not restart it merely because its download exceeds one check interval.
		return job.State == "ready", job.State == "preparing", job.Message
	}
	if a.Updates == nil {
		return false, false, "Проверка версии недоступна."
	}
	check, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result := a.Updates.CheckChannel(check, true, a.autonomyPolicy().UpdateChannel)
	if check.Err() != nil || result.State == "check-failed" {
		return false, false, "Проверка версии не завершена."
	}
	return true, false, "Версия проверена. Автоматическая установка пока закрыта."
}
