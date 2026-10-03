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
	"github.com/ArtixSx/razvilka/internal/maintenancebatch"
)

const componentPendingPrefix = "pending:"

// Keep the receipt in an existing schema-1 slot: adding a third maintenance
// key breaks older strict readers and even 0.19.3's own persistence validator.
// This checkpoint prevents automatic replay. It is not a replacement for the
// component manager's future durable package/configuration rollback journal.
func (a *App) componentMaintenancePending() bool {
	if a.PendingComponentRecovery() {
		return true
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return strings.HasPrefix(a.autonomy.doc.Maintenance["components"], componentPendingPrefix)
}

func componentMaintenanceAllowed(p autonomy.Policy, cfg config.Config, dirty bool, revision uint64, slot string, now time.Time) bool {
	current, open := autonomy.WindowKey(p.Components, p.Timezone, now)
	return p.SetupComplete && p.Components.Mode == "install" && open && current == slot &&
		!cfg.SafeMode && !cfg.ServiceControl.Stopped && cfg.ServiceControl.EffectiveMode() != "manual" && !dirty && cfg.Revision == revision
}

func (a *App) runAutomaticComponentBatch(ctx context.Context, views []components.View) maintenancebatch.Result {
	if a.Store == nil || a.Components == nil {
		return maintenancebatch.Result{Message: "Менеджер компонентов или настройки недоступны."}
	}
	if a.componentMaintenancePending() {
		return maintenancebatch.Result{RecoveryRequired: true, Message: "Есть незавершённое обновление компонента. Автоматические изменения остановлены до проверки результата."}
	}
	p := a.autonomyPolicy()
	revision := a.Store.Get().Revision
	slot, open := autonomy.WindowKey(p.Components, p.Timezone, time.Now())
	if !open {
		return maintenancebatch.Result{Message: "Окно установки компонентов закрыто."}
	}
	guard := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		if !reflect.DeepEqual(a.autonomyPolicy(), p) ||
			!componentMaintenanceAllowed(p, a.Store.Get(), a.Store.Dirty(), revision, slot, time.Now()) {
			return errors.New("automatic component maintenance authority changed")
		}
		return a.autonomyDiskCurrent(c)
	}
	items := make([]maintenancebatch.Item, 0, len(views))
	for _, v := range views {
		if v.Installed && v.CanUpdate && !v.ExternalOwner {
			items = append(items, maintenancebatch.Item{ID: v.ID, Name: v.Name, Package: v.Package})
		}
	}
	return maintenancebatch.Run(ctx, items, 7*time.Minute, maintenancebatch.Hooks{
		Guard: guard,
		Begin: func(c context.Context, i maintenancebatch.Item) error { return a.beginComponentMaintenance(c, p, i.ID) },
		Update: func(c context.Context, i maintenancebatch.Item) (maintenancebatch.Outcome, error) {
			// The same guard runs again after preflight, immediately before package IO.
			err := a.updateComponent(c, i.ID, guard)
			switch {
			case err == nil:
				return maintenancebatch.Updated, nil
			case errors.Is(err, components.ErrRollbackUnconfirmed):
				return maintenancebatch.Unknown, err
			case errors.Is(err, components.ErrRollbackVerified):
				return maintenancebatch.RolledBack, err
			case errors.Is(err, components.ErrNoMutation):
				return maintenancebatch.NotStarted, err
			default:
				return maintenancebatch.Unknown, err
			}
		},
		Finish: func(c context.Context, i maintenancebatch.Item, _ maintenancebatch.Outcome) error {
			return a.finishComponentMaintenance(c, i.ID)
		},
	})
}

func (a *App) beginComponentMaintenance(ctx context.Context, p autonomy.Policy, id string) error {
	if !autonomy.ValidID(id) || len(componentPendingPrefix)+len(id) > 64 {
		return errors.New("invalid maintenance component")
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.blocked || !a.autonomy.loaded || !reflect.DeepEqual(a.autonomy.doc.Policy, p) {
		return maintenancebatch.ErrPending
	}
	old, had := a.autonomy.doc.Maintenance["components"]
	if strings.HasPrefix(old, componentPendingPrefix) {
		return maintenancebatch.ErrPending
	}
	a.autonomy.doc.Maintenance["components"] = componentPendingPrefix + id
	if err := a.persistAutonomyLocked(ctx); err != nil {
		if had {
			a.autonomy.doc.Maintenance["components"] = old
		} else {
			delete(a.autonomy.doc.Maintenance, "components")
		}
		return err
	}
	return nil
}

// Call only after the updater proved no mutation, a checked update, or a
// verified rollback. Never clear an unknown outcome on timer/restart alone.
func (a *App) finishComponentMaintenance(ctx context.Context, id string) error {
	if a.PendingComponentRecovery() {
		return maintenancebatch.ErrPending
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	old := a.autonomy.doc.Maintenance["components"]
	if old != componentPendingPrefix+id {
		return maintenancebatch.ErrPending
	}
	delete(a.autonomy.doc.Maintenance, "components")
	if err := a.persistAutonomyLocked(ctx); err != nil {
		a.autonomy.doc.Maintenance["components"] = old
		return err
	}
	return nil
}

// An explicit checked update is also a repair path for this exact component's
// checkpoint. A timer, source refresh or another component cannot clear it.
func (a *App) finishMatchingComponentMaintenance(ctx context.Context, id string) error {
	a.autonomy.mu.Lock()
	matching := a.autonomy.doc.Maintenance["components"] == componentPendingPrefix+id
	a.autonomy.mu.Unlock()
	if !matching {
		return nil
	}
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	return a.finishComponentMaintenance(c, id)
}
