package app

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

type servicePolicyView struct {
	Policy    config.ServicePolicy `json:"policy"`
	Persisted bool                 `json:"persisted"`
	State     string               `json:"state"`
	Reason    string               `json:"reason"`
}

func servicePolicyCapabilities() map[string]any {
	return map[string]any{"automatic_engines": []string{"sing-box"}, "automatic_selector": "applied-fallback-group", "scenario_kinds": []string{"web"},
		"udp": false, "ipv6": false, "egress_country": false, "terminal_actions": []string{"retain"}, "automatic_feed_candidates": false, "credential_recovery": false,
		"note": "Автопроверка и замена доступны для применённой резервной группы Sing-box. Новые узлы из подписок пока не добавляются в резерв автоматически."}
}

func (a *App) servicePolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Store == nil {
		http.Error(w, "Service policy store unavailable", http.StatusServiceUnavailable)
		return
	}
	cfg := a.Store.Get()
	snapshot := nodestore.Snapshot{}
	if a.Nodes != nil {
		var err error
		snapshot, err = a.Nodes.Snapshot(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "Service policy metadata unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	views := map[string]servicePolicyView{}
	for _, service := range a.catalogSnapshot().Services {
		p, exists := cfg.ServicePolicies[service.ID]
		if !exists {
			p = proposedServicePolicy(service.ID, cfg.AppliedServices[service.ID], snapshot)
		}
		state, reason := servicePolicyState(cfg, p)
		views[service.ID] = servicePolicyView{Policy: p, Persisted: exists, State: state, Reason: reason}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": config.ServicePolicySchema, "config_revision": cfg.Revision, "policies": views, "capabilities": servicePolicyCapabilities(), "reconciler": a.reconcilerSnapshot()})
}

func (a *App) servicePolicyUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/service-policies/")
	var request struct {
		ConfigRevision   uint64               `json:"config_revision"`
		ExpectedRevision uint64               `json:"expected_revision"`
		Policy           config.ServicePolicy `json:"policy"`
		Confirm          string               `json:"confirm"`
	}
	if !decodeNodeMutation(w, r, &request) {
		return
	}
	if request.Confirm != "SAVE_SERVICE_POLICY" || a.Store == nil {
		http.Error(w, "invalid service policy request", http.StatusBadRequest)
		return
	}
	known := false
	for _, service := range a.catalogSnapshot().Services {
		if service.ID == id {
			known = true
			break
		}
	}
	if !known {
		http.Error(w, "unknown service", http.StatusNotFound)
		return
	}
	p := request.Policy
	p.ServiceID = id
	p.Schema = config.ServicePolicySchema
	p.LegacyOptIn = false
	var err error
	p, err = config.NormalizeServicePolicy(p)
	if err != nil {
		http.Error(w, "invalid service policy", http.StatusBadRequest)
		return
	}
	if p.Enabled && p.Mode == "auto" {
		if a.Nodes == nil {
			http.Error(w, "node metadata unavailable", http.StatusServiceUnavailable)
			return
		}
		snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "node metadata unavailable", http.StatusServiceUnavailable)
			return
		}
		// IDs are references, never URLs. Every selected member/source must exist.
		for _, id := range p.AllowedNodeIDs {
			found := false
			for _, n := range snapshot.Nodes {
				if n.ID == id {
					found = true
					break
				}
			}
			if !found {
				http.Error(w, "unknown policy node", http.StatusBadRequest)
				return
			}
		}
		for _, id := range p.AllowedSourceIDs {
			found := false
			for _, s := range snapshot.Sources {
				if s.ID == id {
					found = true
					break
				}
			}
			if !found {
				http.Error(w, "unknown policy source", http.StatusBadRequest)
				return
			}
		}
	}
	p, err = a.Store.UpdateServicePolicy(p, request.ConfigRevision, request.ExpectedRevision)
	if err != nil {
		status := http.StatusBadRequest
		code := "SERVICE_POLICY_INVALID"
		if errors.Is(err, config.ErrRevisionChanged) {
			status = http.StatusConflict
			code = "SERVICE_POLICY_CHANGED"
		}
		writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": "Правило или настройки изменились. Обновите страницу и проверьте область устройств."})
		return
	}
	a.wakeReconciler()
	a.nodeAutofallback.mu.Lock()
	if entry, exists := a.nodeAutofallback.entries[id]; exists {
		entry.status.NextCheckAt = time.Time{}
		a.nodeAutofallback.entries[id] = entry
	}
	a.nodeAutofallback.mu.Unlock()
	state, reason := servicePolicyState(a.Store.Get(), p)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": p, "state": state, "reason": reason, "config_revision": a.Store.Get().Revision, "live_applied": false})
}

func proposedServicePolicy(id string, applied config.ServiceState, snapshot nodestore.Snapshot) config.ServicePolicy {
	p := config.DefaultServicePolicy(id, applied)
	for _, g := range snapshot.Groups {
		if selectedRoute(applied) != "sing-box:"+g.ID || g.Mode != "fallback" {
			continue
		}
		p.GroupID = g.ID
		p.AllowedNodeIDs = append([]string{}, g.NodeIDs...)
		p.HoldDownSeconds = g.HoldDownSeconds
		for _, n := range snapshot.Nodes {
			if !slices.Contains(g.NodeIDs, n.ID) {
				continue
			}
			for _, o := range n.Origins {
				for _, s := range snapshot.Sources {
					if o.SourceID == s.ID {
						p.AllowedSourceIDs = append(p.AllowedSourceIDs, s.ID)
						p.TrustClasses = append(p.TrustClasses, s.Kind)
					}
				}
			}
		}
		break
	}
	p, _ = config.NormalizeServicePolicy(p)
	return p
}

// Called only with ordinary admission and before automatic dispatch. The first
// snapshot records legacy fallback consent; later feed/group growth is excluded.
func (a *App) preserveLegacyServicePolicies(ctx context.Context) error {
	if a.Store == nil || a.Nodes == nil {
		return nil
	}
	cfg := a.Store.Get()
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return err
	}
	var policies []config.ServicePolicy
	for id, applied := range cfg.AppliedServices {
		if !applied.Enabled {
			continue
		}
		if _, exists := cfg.ServicePolicies[id]; exists {
			continue
		}
		p := proposedServicePolicy(id, applied, snapshot)
		if p.GroupID == "" {
			continue
		}
		p.Enabled = true
		p.Mode = "auto"
		p.CheckIntervalSeconds = 60
		policies = append(policies, p)
	}
	return a.Store.PreserveLegacyServicePolicies(policies, cfg.Revision)
}

func servicePolicyState(cfg config.Config, p config.ServicePolicy) (string, string) {
	if cfg.ServiceControl.Stopped {
		return "paused", "Маршруты проекта остановлены. Автоматическая замена приостановлена."
	}
	if cfg.ServiceControl.EffectiveMode() == "manual" {
		return "paused", "Включён общий ручной режим. Автоматическая замена приостановлена."
	}
	if p.Mode == "manual" {
		return "manual", "Выбор закреплён вручную; автоматическая замена отключена."
	}
	if !p.Enabled || p.Mode == "paused" {
		return "paused", "Автоподбор приостановлен. Применённый маршрут сохраняется."
	}
	if p.Mode != "auto" {
		return "manual", "Выбор закреплён вручную; автоматическая замена отключена."
	}
	if cfg.SafeMode {
		return "paused", "Включён безопасный режим."
	}
	applied := cfg.AppliedServices[p.ServiceID]
	if !applied.Enabled || p.GroupID == "" || selectedRoute(applied) != "sing-box:"+p.GroupID {
		return "blocked-by-policy", "Сначала примените резервную группу к этому сервису."
	}
	if !sameNodeRecoveryStrings(applied.Sources, p.DeviceSources) {
		return "blocked-by-policy", "Область устройств изменилась. Проверьте правило автоподбора."
	}
	if !slices.Contains(p.AllowedEngines, "sing-box") || p.Scenario.Kind != "web" || p.Scenario.RequireUDP || p.Scenario.RequireIPv6 || p.Scenario.EgressCountry != "" || p.TerminalAction != "retain" {
		return "blocked-by-capability", "Выбранный сценарий, способ или действие при отказе ещё не поддержаны автоматическим циклом."
	}
	if len(p.AllowedNodeIDs) == 0 || len(p.AllowedSourceIDs) == 0 || len(p.TrustClasses) == 0 {
		return "blocked-by-policy", "Выберите разрешённые подключения, источники и классы доверия."
	}
	return "ready", "Разрешены автоматическая проверка и замена внутри применённой группы."
}

func policyAllowsNode(p config.ServicePolicy, snapshot nodestore.Snapshot, id string, now time.Time) bool {
	if !slices.Contains(p.AllowedNodeIDs, id) {
		return false
	}
	for _, n := range snapshot.Nodes {
		if n.ID != id || n.Disabled {
			continue
		}
		for _, origin := range n.Origins {
			if !now.Before(origin.ExpiresAt) || !slices.Contains(p.AllowedSourceIDs, origin.SourceID) {
				continue
			}
			for _, source := range snapshot.Sources {
				if source.ID == origin.SourceID && slices.Contains(p.TrustClasses, source.Kind) {
					return true
				}
			}
		}
	}
	return false
}

func (a *App) guardFallbackPolicy(ctx context.Context, intent nodeAutofallbackIntent, checkNode bool) error {
	if control := a.Store.Get().ServiceControl; control.Stopped || control.EffectiveMode() == "manual" {
		return dataplane.ErrReviewChanged
	}
	p, exists := intent.base.config.ServicePolicies[intent.base.plan.Routes[intent.routeIndex].ServiceID]
	if !exists {
		return nil
	} // Legacy callers; production migrates before dispatch.
	current := a.Store.Get()
	latest, ok := current.ServicePolicies[p.ServiceID]
	if !ok || !reflect.DeepEqual(p, latest) {
		return dataplane.ErrReviewChanged
	}
	state, _ := servicePolicyState(current, latest)
	if state != "ready" {
		return dataplane.ErrReviewChanged
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return err
	}
	if checkNode && !policyAllowsNode(p, snapshot, intent.nodeID, time.Now()) {
		return dataplane.ErrReviewChanged
	}
	if checkNode && p.PinnedNodeID != "" && intent.nodeID != p.PinnedNodeID && !p.PinFallback {
		return dataplane.ErrReviewChanged
	}
	return ctx.Err()
}
