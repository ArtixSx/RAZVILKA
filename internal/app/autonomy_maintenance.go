package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Retry data is process-local: retrying read/check/prepare after a restart is
// safe. Only successfully fulfilled windows are persisted in the existing
// schema. The "install" mode updates RAZVILKA and the installed bypass
// components by itself (the owner's standard); it grants no registration.

// A version whose automatic installation was rolled back is not installed
// again automatically; the next newer version is.
const autoInstallReceipt = "application-install"

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
			if view.CatalogStale || view.UpdateCheckError != "" || view.InventoryError != "" || view.State == "check-failed" || view.State == "installed-check-failed" {
				return false, false, "Источник части компонентов недоступен. Существующие версии сохранены; проверка будет повторена."
			}
		}
		// While each installed version is still offered, keep its copy for the
		// rollback of a later in-use update.
		a.cacheManagedRollbackPackages(check)
		if w.Mode != "install" {
			return true, false, "Каталог компонентов проверен. Автоматическая установка не включена."
		}
		return true, false, a.autoUpdateComponents(ctx, views)
	}
	if w.Mode == "prepare" || w.Mode == "install" {
		if a.SelfUpdate == nil || a.Store == nil {
			return false, false, "Подготовка обновления недоступна."
		}
		current := a.SelfUpdate.Snapshot()
		switch current.State {
		case "ready":
			fresh := !current.UpdatedAt.IsZero() && !current.UpdatedAt.After(time.Now()) && time.Since(current.UpdatedAt) < 15*time.Minute
			if fresh && current.ConfigRevision == a.Store.Get().Revision && updatecheck.NormalizedChannel(current.Channel) == updatecheck.NormalizedChannel(a.autonomyPolicy().UpdateChannel) {
				if w.Mode == "install" {
					a.autonomy.mu.Lock()
					job := current
					a.autonomy.autoInstall = &job
					a.autonomy.mu.Unlock()
					return false, true, "Архив подготовлен и проверен. Запускается установка; при сбое вернётся прежняя версия."
				}
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
		if w.Mode == "install" && a.autoInstallFailed(latest.LatestVersion) {
			return true, false, "Версия " + latest.LatestVersion + " не установилась автоматически, прежняя сохранена. Установится следующая версия; эту можно поставить вручную."
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

// autoInstallFailed reports that this version was handed to the installer
// automatically before and this process still runs another version: the
// installer rolled it back.
func (a *App) autoInstallFailed(version string) bool {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	attempted := a.autonomy.doc.Maintenance[autoInstallReceipt]
	return version != "" && attempted == version && Version != version
}

// autoInstallAllowed reports whether a prepared package may be installed now:
// it was prepared for these exact settings and channel, and the network is
// not stopped, protected or waiting for the owner's review of a draft.
func autoInstallAllowed(job updatecheck.Job, cfg config.Config, dirty bool, p autonomy.Policy) bool {
	return job.Release != nil && job.State == "ready" && job.ID != "" && job.ReviewToken != "" &&
		!cfg.SafeMode && !cfg.ServiceControl.Stopped && !dirty && cfg.Revision == job.ConfigRevision &&
		updatecheck.NormalizedChannel(job.Channel) == updatecheck.NormalizedChannel(p.UpdateChannel)
}

// runAutoInstall hands a prepared, verified package to the installer. It runs
// under the round's exclusive admission and reports whether that admission now
// belongs to the handoff, which the installer releases by restarting.
func (a *App) runAutoInstall(ctx context.Context, p autonomy.Policy) bool {
	a.autonomy.mu.Lock()
	job := a.autonomy.autoInstall
	a.autonomy.autoInstall = nil
	a.autonomy.mu.Unlock()
	if job == nil || a.SelfUpdate == nil || a.Store == nil || ctx.Err() != nil {
		return false
	}
	cfg := a.Store.Get()
	if !autoInstallAllowed(*job, cfg, a.Store.Dirty(), p) || a.autoInstallFailed(job.Release.Version) {
		return false
	}
	// Record the attempt before the handoff: after a rollback the old process
	// starts again and must not repeat the same version every night.
	a.autonomy.mu.Lock()
	if a.autonomy.blocked || !reflect.DeepEqual(a.autonomy.doc.Policy, p) {
		a.autonomy.mu.Unlock()
		return false
	}
	old, had := a.autonomy.doc.Maintenance[autoInstallReceipt]
	a.autonomy.doc.Maintenance[autoInstallReceipt] = job.Release.Version
	if err := a.persistAutonomyLocked(ctx); err != nil {
		if had {
			a.autonomy.doc.Maintenance[autoInstallReceipt] = old
		} else {
			delete(a.autonomy.doc.Maintenance, autoInstallReceipt)
		}
		a.autonomy.mu.Unlock()
		return false
	}
	a.autonomy.mu.Unlock()
	started, err := a.SelfUpdate.Apply(ctx, job.ID, job.ReviewToken, cfg.Revision, updatecheck.ConfigFingerprint(cfg))
	if err != nil && !errors.Is(err, updatecheck.ErrHandoffUncertain) {
		a.autonomy.mu.Lock()
		a.autonomy.maintenanceMessage = "Автоматическая установка " + job.Release.Version + " не запущена: " + started.Message
		a.autonomy.mu.Unlock()
		return false
	}
	a.autonomy.mu.Lock()
	a.autonomy.maintenanceMessage = "Устанавливается RAZVILKA " + job.Release.Version + ". Панель ненадолго перезапустится; при сбое вернётся прежняя версия."
	a.autonomy.mu.Unlock()
	return true
}

// autoUpdateComponents updates every installed component with a newer
// package, the way the panel's "Update" does: with an isolated check and a
// rollback while routes use it, plainly otherwise.
func (a *App) autoUpdateComponents(ctx context.Context, views []components.View) string {
	updated, failed := []string{}, []string{}
	for _, view := range views {
		if ctx.Err() != nil {
			break
		}
		if !view.Installed || !view.CanUpdate || view.ExternalOwner {
			continue
		}
		update, cancel := context.WithTimeout(ctx, 7*time.Minute)
		err := a.updateComponent(update, view.ID)
		cancel()
		if err != nil {
			failed = append(failed, view.Name)
		} else {
			updated = append(updated, view.Name)
		}
	}
	switch {
	case len(updated) == 0 && len(failed) == 0:
		return "Каталог компонентов проверен. Обновлений нет."
	case len(failed) == 0:
		return "Обновлено: " + strings.Join(updated, ", ") + "."
	case len(updated) == 0:
		return "Не обновлено (прежние версии сохранены): " + strings.Join(failed, ", ") + "."
	}
	return "Обновлено: " + strings.Join(updated, ", ") + ". Не обновлено (прежние версии сохранены): " + strings.Join(failed, ", ") + "."
}
