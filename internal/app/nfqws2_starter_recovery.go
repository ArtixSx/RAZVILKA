package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type nfqws2StarterRepairMember struct {
	spec    autonomy.Service
	service catalog.Service
}

// Restarting the common process restores every applied assignment at once.
// Match the complete applied set and the consent for every service in it.
func (a *App) nfqws2StarterRepairMembers(p autonomy.Policy, cfg config.Config, plan dataplane.Plan) []nfqws2StarterRepairMember {
	if !nfqws2HookAppliedPlan(cfg, plan) || !slices.Equal(plan.Adapters, []string{"nfqws2"}) {
		return nil
	}
	for id, state := range cfg.AppliedServices {
		if state.Enabled && !slices.ContainsFunc(plan.Routes, func(route dataplane.Route) bool { return route.ServiceID == id }) {
			return nil
		}
	}
	members := make([]nfqws2StarterRepairMember, 0, len(plan.Routes))
	a.autonomy.mu.Lock()
	for _, route := range plan.Routes {
		spec, ok := a.autonomy.doc.Services[route.ServiceID]
		if !ok || !a.autonomyConsentLocked(p, spec) || spec.Removing ||
			(len(plan.Routes) > 1 && spec.ExpectedRoute != "auto") || !nfqws2StarterApplied(cfg, spec.ID) ||
			autonomyDraftFingerprint(cfg.Services[spec.ID]) != spec.DraftFingerprint {
			a.autonomy.mu.Unlock()
			return nil
		}
		members = append(members, nfqws2StarterRepairMember{spec: spec})
	}
	a.autonomy.mu.Unlock()
	for i, member := range members {
		service, ok := a.autonomyService(member.spec.ID)
		if !ok || !catalog.IsNFQWS2Starter(service) || !nfqws2FirstStartScope(member.spec, service) ||
			autonomyDefinition(service) != member.spec.Definition || !nodeRecoveryServiceMatches(plan.Routes[i], service) {
			return nil
		}
		members[i].service = service
	}
	slices.SortFunc(members, func(a, b nfqws2StarterRepairMember) int { return strings.Compare(a.spec.ID, b.spec.ID) })
	return members
}

func (a *App) repairAutonomyNFQWS2Starter(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, service catalog.Service, cfg config.Config, profile string) (autonomy.Runtime, bool) {
	finish := func(state, message string) (autonomy.Runtime, bool) {
		r.State, r.Message = state, message
		return r, true
	}
	if a.autonomyRouteBlockReason(p, cfg) != "" || !nfqws2FirstStartScope(s, service) || !nfqws2StarterApplied(cfg, s.ID) {
		return r, false
	}
	if !slices.Contains(p.PreferredRoutes, "nfqws2") {
		return finish("capability-refused", "NFQWS2 выключен в автоподборе. Сохранённое назначение не будет перезапущено.")
	}
	manager, store := a.Dataplane, a.Store
	plan, found, err := manager.Committed()
	if err != nil || !found {
		return r, false
	}
	members := a.nfqws2StarterRepairMembers(p, cfg, plan)
	if len(members) == 0 || !slices.ContainsFunc(members, func(member nfqws2StarterRepairMember) bool { return reflect.DeepEqual(member.spec, s) }) {
		return r, false
	}
	// One stable service owns the common process's repair budget. Other
	// services can observe the outcome, but cannot spend a separate budget.
	if members[0].spec.ID != s.ID {
		return finish("unconfirmed", "Общий процесс NFQWS2 остановлен. Автопилот проверит возможность его восстановления для всех подключённых сервисов.")
	}
	guard := func(c context.Context) error {
		if c.Err() != nil || a.Dataplane != manager || a.Store != store || !reflect.DeepEqual(store.Get(), cfg) ||
			a.nfqws2HookSuspended(c, cfg) || a.hasDueRuntimeStop(time.Now()) || a.autonomyDiskCurrent(c) != nil {
			return dataplane.ErrReviewChanged
		}
		current, err := a.freshNetworkProfile(c)
		if err != nil || current != profile {
			return dataplane.ErrNetworkChanged
		}
		// The runtime reuses compiled exclusions. Also compare the current
		// catalog expansion of excluded services before reviving those rules.
		sites, err := a.legacySiteExclusions(cfg)
		if err != nil || !dataplane.SameSiteExclusions(sites, plan.SiteExclusions) ||
			!slices.Equal(sites.ExcludedDomains(), plan.SiteExclusions.ExcludedDomains()) ||
			!slices.Equal(sites.ExcludedCIDRs(), plan.SiteExclusions.ExcludedCIDRs()) {
			return dataplane.ErrReviewChanged
		}
		for _, member := range members {
			if err := a.autonomyResourceGuard(c, p, member.spec, cfg, member.service); err != nil {
				return err
			}
		}
		return nil
	}
	if guard(ctx) != nil {
		return finish("paused", "Условия восстановления NFQWS2 изменились. Сохранённое назначение не менялось.")
	}
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		r.NextCheck = r.SwitchBudgetAt(time.Now(), p.MaxSwitchesPerHour)
		return finish("rate-limited", "Лимит попыток исчерпан. Восстановление NFQWS2 отложено.")
	}
	r.State, r.Message = "applying", "Проверяем возможность восстановить действующий профиль NFQWS2."
	if !a.autonomyRuntime(p.Revision, s.ID, r) {
		r.RefundSwitch()
		return finish("requires-review", "Не удалось сохранить состояние восстановления NFQWS2. Сеть не менялась.")
	}
	review := dataplane.WithRecoveryReview(dataplane.WithReviewGuard(ctx, guard), func(current dataplane.Plan) error {
		if !reflect.DeepEqual(current, plan) {
			return dataplane.ErrReviewChanged
		}
		return nil
	})
	if err := manager.RepairCommittedNFQWS2FirstStart(review, plan); err != nil {
		if retry := time.Now().Add(time.Minute); r.NextCheck.Before(retry) {
			r.NextCheck = retry
		}
		if errors.Is(err, dataplane.ErrNFQWS2FirstStartRepairUnavailable) {
			r.RefundSwitch()
			return finish("component-stopped", "NFQWS2 остановлен. Без подтверждения отсутствия прежнего процесса и правил автоматический перезапуск недоступен.")
		}
		return finish("unconfirmed", "Восстановление NFQWS2 не подтверждено. Автопилот проверит действующий путь повторно.")
	}
	nextCheck := time.Now().Add(reconcilerPollInterval)
	const repaired = "NFQWS2 перезапущен с сохранённым профилем. Автопилот проверит HTTPS сервиса через действующую очередь."
	checkAgain := func(runtime *autonomy.Runtime) {
		runtime.State, runtime.Message = "applied", repaired
		runtime.Failures = 0
		runtime.FirstFailure, runtime.LastFailure = time.Time{}, time.Time{}
		runtime.CheckedAt, runtime.NextCheck = time.Time{}, nextCheck
	}
	checkAgain(&r)
	for _, item := range members[1:] {
		id := item.spec.ID
		a.autonomy.mu.Lock()
		peer := a.autonomy.doc.Runtime[id].Clone()
		a.autonomy.mu.Unlock()
		checkAgain(&peer)
		if !a.autonomyRuntime(p.Revision, id, peer) {
			return finish("requires-review", "NFQWS2 перезапущен, но не удалось сохранить состояние общей проверки.")
		}
	}
	return r, true
}
