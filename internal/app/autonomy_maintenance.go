package app

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// The scheduled operations here are read/check/prepare only. Unattended package
// mutation remains closed until signed compatibility metadata and rollback are
// available. Never substitute `opkg upgrade` for a component transaction.
func (a *App) autonomyMaintenance(ctx context.Context, p autonomy.Policy, now time.Time) {
	for _, task := range []struct {
		name   string
		window autonomy.Window
	}{{"application", p.Application}, {"components", p.Components}} {
		slot, open := autonomy.WindowKey(task.window, p.Timezone, now)
		if !open || ctx.Err() != nil {
			continue
		}
		a.autonomy.mu.Lock()
		if a.autonomy.doc.Maintenance[task.name] == slot {
			a.autonomy.mu.Unlock()
			continue
		}
		a.autonomy.doc.Maintenance[task.name] = slot
		err := a.persistAutonomyLocked(ctx)
		a.autonomy.mu.Unlock()
		if err != nil {
			return
		}
		message := "Проверка обновлений завершена. Автоматическая установка пока закрыта."
		if task.name == "components" {
			if a.Components == nil {
				message = "Менеджер компонентов недоступен."
			} else {
				check, cancel := context.WithTimeout(ctx, 90*time.Second)
				_, err = a.Components.List(check, true)
				cancel()
				if err != nil {
					message = "Не удалось проверить каталог компонентов. Установленные версии не изменены."
				}
			}
		} else {
			if a.SelfUpdate == nil {
				message = "Менеджер обновления приложения недоступен."
			} else if task.window.Mode == "prepare" {
				cfg := a.Store.Get()
				job, e := a.SelfUpdate.Prepare(cfg.Revision, updatecheck.ConfigFingerprint(cfg))
				if e != nil {
					message = "Подготовка отложена: установщик занят или условия не выполнены."
				} else {
					message = job.Message
				}
			} else {
				// Existing checker only reads stable release metadata. No executable is run.
				check, cancel := context.WithTimeout(ctx, 30*time.Second)
				if a.Updates == nil {
					err = context.Canceled
				} else {
					result := a.Updates.Check(check, true)
					if result.State == "check-failed" {
						err = context.Canceled
					} else {
						err = nil
					}
				}
				cancel()
				if err != nil {
					message = "Проверка версии не завершена; повтор в следующем окне."
				}
			}
		}
		a.autonomy.mu.Lock()
		a.autonomy.maintenanceMessage = message
		a.autonomy.mu.Unlock()
	}
}
