package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Only explicit creation/enabling by the user calls this hook. Startup, feed
// refresh and profile/backup import must never enroll arbitrary old drafts.
func (a *App) inheritAutonomyService(ctx context.Context, id string) error {
	if err := a.loadAutonomy(ctx); err != nil {
		return err
	}
	p := a.autonomyPolicy()
	if !p.SetupComplete || !p.InheritNewServices {
		return nil
	}
	service, ok := a.autonomyService(id)
	if !ok {
		return errors.New("unknown service")
	}
	cfg := a.Store.Get()
	sources, err := config.NormalizeSources(p.DefaultSources)
	if err != nil {
		return err
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.doc.Policy.Revision != p.Revision {
		return dataplane.ErrReviewChanged
	}
	if _, exists := a.autonomy.doc.Services[id]; exists {
		return nil
	}
	if len(a.autonomy.doc.Services) >= autonomy.MaxServices {
		return errors.New("autonomy service limit")
	}
	a.autonomy.doc.Services[id] = autonomy.Service{ID: id, Enabled: true, AllLAN: p.AllLAN, Sources: sources,
		Definition: autonomyDefinition(service), DraftFingerprint: autonomyDraftFingerprint(cfg.Services[id]), ExpectedRoute: selectedRoute(cfg.Services[id])}
	a.autonomy.doc.Runtime[id] = autonomy.Runtime{State: "pending", Message: "Новый сервис унаследовал подтверждённые настройки. Ожидается проверка."}
	a.autonomy.doc.Policy.Revision++
	return a.persistAutonomyLocked(ctx)
}

// Deletion is a persistent intent, not deletion of the live configuration. The
// catalog entry remains until a scoped dataplane transaction completes.
func (a *App) requestAutonomyRemoval(ctx context.Context, id string, deleteDefinition bool) (bool, error) {
	if err := a.loadAutonomy(ctx); err != nil {
		return false, err
	}
	cfg := a.Store.Get()
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	s, exists := a.autonomy.doc.Services[id]
	if !exists {
		return false, nil
	}
	if a.autonomy.doc.Policy.Revision == ^uint64(0) {
		return true, dataplane.ErrReviewChanged
	}
	s.Removing, s.Enabled, s.DeleteDefinition = true, true, deleteDefinition
	s.DraftFingerprint = autonomyDraftFingerprint(cfg.Services[id])
	a.autonomy.doc.Services[id] = s
	a.autonomy.doc.Runtime[id] = autonomy.Runtime{State: "removal-pending", Message: "Сначала будут сняты собственные маршруты сервиса. Остальные сервисы сохраняются."}
	a.autonomy.doc.Policy.Revision++
	return true, a.persistAutonomyLocked(ctx)
}

func (a *App) autonomyRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/autonomy/services/")
	var req struct {
		ExpectedRevision uint64 `json:"expected_revision"`
		Confirm          string `json:"confirm"`
		DeleteDefinition bool   `json:"delete_definition"`
	}
	if !decodeAutonomyRequest(w, r, &req) {
		return
	}
	if a.loadAutonomy(r.Context()) != nil {
		writeJSON(w, 503, map[string]any{"error": "Хранилище недоступно."})
		return
	}
	p := a.autonomyPolicy()
	if req.Confirm != "REMOVE_SERVICE" || !autonomy.ValidID(id) || req.ExpectedRevision != p.Revision {
		writeJSON(w, 409, map[string]any{"error": "Подтвердите удаление для актуальной редакции настроек."})
		return
	}
	handled, err := a.requestAutonomyRemoval(r.Context(), id, req.DeleteDefinition)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "Запрос удаления не сохранён; рабочая сеть не изменена."})
		return
	}
	if !handled {
		writeJSON(w, 404, map[string]any{"error": "Сервис не управляется автономным режимом."})
		return
	}
	a.wakeReconciler()
	writeJSON(w, 202, map[string]any{"ok": true, "pending": true, "live_applied": false, "notice": "Снятие маршрута выполняется в очереди. Safe Mode, ручной режим и пауза автоматики сохраняют запрет изменений."})
}

func (a *App) runAutonomyRemoval(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime) autonomy.Runtime {
	finish := func(state, message string) autonomy.Runtime { r.State, r.Message = state, message; return r }
	if !s.Removing || !a.autonomyConsent(p, s) {
		return finish("paused", "Удаление отменено.")
	}
	base := a.Store.Get()
	status, err := a.Dataplane.Status()
	if err != nil || status.Execution != nil && status.Execution.State == "rollback-failed" {
		return finish("requires-review", "Сначала требуется восстановить журнал применения.")
	}
	service, known := a.autonomyService(s.ID)
	if known && autonomyDefinition(service) != s.Definition {
		return finish("definition-changed", "Состав сервиса изменён. Повторно подтвердите удаление.")
	}
	if autonomyDraftFingerprint(base.Services[s.ID]) != s.DraftFingerprint && (base.Services[s.ID].Enabled || base.AppliedServices[s.ID].Enabled) {
		return finish("manual-change", "После запроса удаления сервис изменён вручную.")
	}
	if base.AppliedServices[s.ID].Enabled {
		if !known {
			return finish("requires-review", "Каталог не соответствует применённому маршруту; автоматическое удаление остановлено.")
		}
		hypothetical := nodeRouteConfigForScope(base, s.ID, "unused", s.Sources)
		target := hypothetical.Services[s.ID]
		target.Enabled = false
		hypothetical.Services[s.ID] = target
		plan, e := a.buildDataplanePlanForScope(hypothetical, a.nodeRouteOptions(), changeScopeNode, "")
		if e != nil || !plan.Ready {
			return finish("removal-blocked", "Снятие маршрута не прошло предварительную проверку. Конфигурация сохранена.")
		}
		committed := false
		guard := func(ctx context.Context) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
				return dataplane.ErrReviewChanged
			}
			cfg := a.Store.Get()
			revision := base.Revision
			if committed {
				revision++
			}
			if cfg.Revision != revision || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
				return dataplane.ErrReviewChanged
			}
			cat, ok := a.autonomyService(s.ID)
			if !ok || autonomyDefinition(cat) != s.Definition {
				return dataplane.ErrReviewChanged
			}
			return nil
		}
		if e = guard(ctx); e != nil {
			return finish("removal-blocked", "Разрешение или настройки изменились.")
		}
		_, e = a.Dataplane.Apply(dataplane.WithReviewGuard(ctx, guard), plan, func() (func() error, error) {
			if e := guard(ctx); e != nil {
				return nil, e
			}
			undo, e := a.Store.ApplyAutonomyRemovalWithRollback(s.ID, s.DeleteDefinition, base.Revision)
			if e == nil {
				committed = true
			}
			return undo, e
		})
		if e != nil {
			return finish("removal-blocked", "Снятие маршрута не подтверждено; использован общий откат.")
		}
	} else if s.DeleteDefinition && base.Services[s.ID].Enabled {
		// No applied path is allowed to legitimize deleting a newer enabled draft.
		return finish("manual-change", "Сервис включён в черновике. Подтвердите действие в разделе сервисов.")
	}
	// Catalog removal is deliberately last; failure is safely retried. An
	// already absent definition after a crash is idempotent when no path remains.
	if s.DeleteDefinition && known && a.CustomServices != nil && a.CustomServices.Has(s.ID) {
		if e := a.CustomServices.Delete(s.ID); e != nil {
			return finish("removal-pending", "Маршрут снят, но удаление записи каталога нужно повторить.")
		}
	}
	a.autonomy.mu.Lock()
	delete(a.autonomy.doc.Services, s.ID)
	delete(a.autonomy.doc.Runtime, s.ID)
	a.autonomy.doc.Policy.Revision++
	err = a.persistAutonomyLocked(context.WithoutCancel(ctx))
	a.autonomy.mu.Unlock()
	if err != nil {
		return finish("requires-review", "Маршрут снят; запись завершения не подтверждена.")
	}
	r.Reserves = slices.Clone([]string{})
	return finish("removed", "Сервис исключён из автономного управления после снятия его маршрутов.")
}

// Re-enrollment is explicit. This helper does not pretend that a pending removal
// has already affected the live network.
func (a *App) autonomyManaged(ctx context.Context, id string) bool {
	if a.loadAutonomy(ctx) != nil {
		return false
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	_, ok := a.autonomy.doc.Services[id]
	return ok
}
