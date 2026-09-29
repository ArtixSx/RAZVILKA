package app

import (
	"context"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
)

// NFQWS2 is the standard route of the services from the reviewed
// nfqws2-keenetic list, as in z2k where the whole list goes through NFQWS2.
// The autopilot returns such a service to NFQWS2 when its exact node is gone
// (origin expired, disabled or removed), or when the owner already chose
// NFQWS2 in the draft. It never replaces a working node or another choice.
// NFQWS2 cannot be limited to selected devices, so this applies only to an
// autopilot scope of the whole LAN.

// nfqws2StandardScope reports whether the service may use its standard route.
func nfqws2StandardScope(service catalog.Service, s autonomy.Service) bool {
	return catalog.IsNFQWS2Starter(service) && len(s.Sources) == 0
}

// nfqws2StandardDraft reports whether the owner's draft returns an NFQWS2-list
// service to its standard route for the whole LAN.
func nfqws2StandardDraft(service catalog.Service, s autonomy.Service, draft config.ServiceState) bool {
	return nfqws2StandardScope(service, s) && draft.Enabled && selectedRoute(draft) == "nfqws2" && len(draft.Sources) == 0
}

// adoptNFQWS2StandardDraft records the owner's return to NFQWS2 as the
// autopilot's expectation, so the pending change is applied by the scoped
// autopilot transaction instead of pausing automation as a manual change.
func (a *App) adoptNFQWS2StandardDraft(ctx context.Context, p autonomy.Policy, s autonomy.Service, draft config.ServiceState) (autonomy.Service, bool) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	current, ok := a.autonomy.doc.Services[s.ID]
	if a.autonomy.blocked || a.autonomy.doc.Policy.Revision != p.Revision || !ok || !reflect.DeepEqual(current, s) {
		return s, false
	}
	current.ExpectedRoute = "nfqws2"
	current.DraftFingerprint = autonomyDraftFingerprint(draft)
	a.autonomy.doc.Services[s.ID] = current
	if a.persistAutonomyLocked(context.WithoutCancel(ctx)) != nil {
		a.autonomy.doc.Services[s.ID] = s
		return s, false
	}
	return current, true
}

func (a *App) nfqws2RouteReady() bool {
	for _, o := range a.nodeRouteOptions() {
		if o.ID == "nfqws2" && o.Ready {
			return true
		}
	}
	return false
}

// returnToNFQWS2Standard replaces an unavailable exact node of an NFQWS2-list
// service with NFQWS2. The node gives no path at all, so the standard route is
// applied even when the web check through NFQWS2 is not confirmed yet; later
// rounds keep NFQWS2 and never switch the service to another node.
func (a *App) returnToNFQWS2Standard(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, service catalog.Service, cfg config.Config, profile string) autonomy.Runtime {
	finish := func(state, message string) autonomy.Runtime { r.State, r.Message = state, message; return r }
	verdict := a.autonomyProbeRoute(ctx, service, "nfqws2", profile)
	r.CheckedAt = time.Now().UTC()
	if ctx.Err() != nil || !a.autonomyConsent(p, s) || !reflect.DeepEqual(a.Store.Get(), cfg) {
		return finish("paused", "Проверка отменена или изменились настройки. Сеть не изменена.")
	}
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		return finish("rate-limited", "Узел сервиса недоступен. Лимит применений исчерпан; возврат на NFQWS2 отложен.")
	}
	r.State, r.Message = "applying", "Узел сервиса недоступен. Возвращаем штатный NFQWS2."
	a.autonomyRuntime(s.ID, r)
	if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, "nfqws2"); err != nil {
		if state, message, blocked := autonomyRouteDependency(err, &r); blocked {
			return finish(state, message)
		}
		return finish("apply-refused", "Возврат на NFQWS2 не подтверждён после применения. Использована штатная защита и откат.")
	}
	r.Failures, r.FirstFailure, r.LastFailure = 0, time.Time{}, time.Time{}
	r.Reserves = nil
	if verdict != "PASS" {
		return finish("applied", "Узел сервиса был недоступен: сервис возвращён на штатный NFQWS2. Веб-проверка через NFQWS2 пока не подтверждена; назначение сохранено.")
	}
	return finish("applied", "Узел сервиса был недоступен: сервис возвращён на штатный NFQWS2 и проверен.")
}
