package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

const mihomoNodePath = "/api/v1/mihomo/nodes/"

func (a *App) mihomoNodeSelection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Store == nil {
		writeNodeApplyError(w, "MIHOMO_RUNTIME_UNAVAILABLE", "Настройки сейчас недоступны.")
		return
	}
	cfg := a.Store.Get()
	services := []map[string]any{}
	for _, service := range a.catalogSnapshot().Services {
		if mihomoNodePublicService(service) == nil {
			services = append(services, map[string]any{"id": service.ID, "name": service.Name, "enabled": cfg.Services[service.ID].Enabled, "applied_sources": append([]string{}, cfg.AppliedServices[service.ID].Sources...)})
		}
	}
	registered := a.Dataplane != nil && a.Dataplane.MihomoLiveRuntimeRegistered()
	available := registered && a.Dataplane.Capable("mihomo") && a.Dataplane.CanaryCapable("mihomo")
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "revision": cfg.Revision, "services": services, "runtime_registered": registered, "live_apply_available": available, "service_verified": false, "live_applied": false})
}

func mihomoNodeIntent(cfg config.Config, cat catalog.Catalog) string {
	raw, err := json.Marshal(struct {
		Config  config.Config
		Catalog catalog.Catalog
	}{cfg, cat})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (a *App) mihomoNodeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, mihomoNodePath)
	id, action, ok := strings.Cut(tail, "/")
	if !ok || strings.Contains(action, "/") || action != "preview" && action != "apply" {
		http.NotFound(w, r)
		return
	}
	if _, valid := mihomoNodeRouteID("mihomo:" + id); !valid {
		http.Error(w, "Некорректный идентификатор узла.", http.StatusBadRequest)
		return
	}
	if a.Store == nil || a.Nodes == nil || a.Dataplane == nil || !a.Dataplane.MihomoLiveRuntimeRegistered() {
		writeNodeApplyError(w, "MIHOMO_RUNTIME_UNAVAILABLE", "Исходный runtime Mihomo не зарегистрирован. Установленный компонент сам по себе не разрешает применение.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDataplaneApplyTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if action == "preview" {
		a.mihomoNodePreview(w, r, id)
		return
	}
	a.mihomoNodeApply(w, r, id)
}

func (a *App) mihomoNodePreview(w http.ResponseWriter, r *http.Request, id string) {
	var request struct {
		ServiceID        string   `json:"service_id"`
		Sources          []string `json:"sources"`
		ExpectedRevision *uint64  `json:"expected_revision"`
	}
	if !decodeNodeMutation(w, r, &request) {
		return
	}
	cfg := a.Store.Get()
	if request.ExpectedRevision == nil || *request.ExpectedRevision != cfg.Revision || cfg.Revision == ^uint64(0) {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Обновите настройки перед просмотром.")
		return
	}
	sources, err := config.NormalizeMihomoNodeSources(request.Sources)
	if err != nil {
		writeNodeApplyError(w, "MIHOMO_SCOPE_UNSUPPORTED", "Явно выберите частные IPv4-адреса или сети устройств.")
		return
	}
	cat := a.catalogSnapshot()
	var service catalog.Service
	for _, candidate := range cat.Services {
		if candidate.ID == request.ServiceID {
			service = defaultRouteCloneCatalogService(candidate)
			break
		}
	}
	if service.ID == "" || a.nodeServiceResourceAdmission(r.Context(), cfg, service.ID) != nil {
		writeNodeApplyError(w, "MIHOMO_SERVICE_REFUSED", "Выберите доступный сервис без исключений.")
		return
	}
	preview := nodeRouteConfigForEngineScope(cfg, "mihomo", service.ID, id, sources)
	if err = mihomoNodeServiceScope(preview, service, sources); err != nil {
		writeNodeApplyError(w, "MIHOMO_SCOPE_UNSUPPORTED", "Доступен один сервис с публичными IPv4-сетями и явно выбранными устройствами. Домены и смешанные маршруты пока не поддерживаются.")
		return
	}
	node, err := a.reviewMihomoNode(r.Context(), "mihomo:"+id)
	if err != nil {
		writeNodeApplyError(w, "MIHOMO_NODE_UNSUPPORTED", "Нужен конкретный узел VLESS/TCP/TLS с проверкой сертификата.")
		return
	}
	plan, err := a.buildDataplanePlanForScopeContext(r.Context(), preview, a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil {
		writeNodePlanFailure(w, err)
		return
	}
	review := nodeRouteReview{Engine: "mihomo", Revision: cfg.Revision, Generation: node.Reference().NodeGeneration, NodeID: id, ServiceID: service.ID, NetworkProfile: plan.NetworkProfileID, Digest: plan.Digest, ExpiresAt: time.Now().Add(nodeReviewTTL), ScopeSelection: "selected", scopeSources: sources, owner: nodeReviewOwner(r), intentHash: mihomoNodeIntent(cfg, cat)}
	if node.Current(r.Context()) != nil || review.intentHash == "" || review.intentHash != mihomoNodeIntent(a.Store.Get(), a.catalogSnapshot()) {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Настройки, каталог или узел изменились. Откройте новый план.")
		return
	}
	ready := plan.Ready && a.Dataplane.Capable("mihomo") && a.Dataplane.CanaryCapable("mihomo")
	if ready {
		review, err = a.nodeReviews.put(review, time.Now())
		if err != nil {
			writeNodeApplyError(w, "MIHOMO_REVIEW_UNAVAILABLE", "Не удалось сохранить подтверждение. Повторите просмотр.")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "ok": true, "ready": ready, "review": review, "transaction": plan, "engine": "mihomo", "service_name": service.Name, "effective_scope": nodeScopePresentation(sources), "live_applied": false, "service_verified": false, "note": "Просмотр проверяет исходные данные. Применение должно заново подтвердить все обязательные сценарии через Mihomo и TUN; результаты других движков не используются."})
}

func (a *App) mihomoNodeApply(w http.ResponseWriter, r *http.Request, id string) {
	var request nodeApplyRequest
	if !decodeNodeMutation(w, r, &request) {
		return
	}
	if request.Engine != "mihomo" || request.Confirm != "APPLY_MIHOMO_NODE_ROUTE" || request.IdempotencyKey != "" {
		writeNodeApplyError(w, "MIHOMO_REVIEW_REQUIRED", "Просмотрите выбранный маршрут Mihomo и явно подтвердите применение.")
		return
	}
	review, ok := a.nodeReviews.take(request.Token, nodeReviewOwner(r), time.Now())
	if !ok || review.Engine != "mihomo" || review.NodeID != id || review.ServiceID != request.ServiceID || review.Digest != request.Digest || review.Revision != request.Revision || review.Generation != request.Generation {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Подтверждение устарело или относится к другому выбору.")
		return
	}
	if !a.Dataplane.Capable("mihomo") || !a.Dataplane.CanaryCapable("mihomo") {
		writeNodeApplyError(w, "MIHOMO_RUNTIME_UNAVAILABLE", "Полный цикл применения Mihomo пока не разрешён для этого runtime.")
		return
	}
	cfg, cat := a.Store.Get(), a.catalogSnapshot()
	if cfg.Revision != review.Revision || review.intentHash != mihomoNodeIntent(cfg, cat) {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Настройки или каталог изменились. Откройте новый план.")
		return
	}
	node, err := a.reviewMihomoNode(r.Context(), "mihomo:"+id)
	if err != nil || node.Reference().NodeGeneration != review.Generation {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Источник узла изменился. Откройте новый план.")
		return
	}
	plan, err := a.buildDataplanePlanForScopeContext(r.Context(), nodeRouteConfigForEngineScope(cfg, "mihomo", review.ServiceID, id, review.scopeSources), a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || !plan.Ready || plan.Digest != review.Digest || plan.NetworkProfileID != review.NetworkProfile || len(plan.Routes) != 1 {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Состав или условия маршрута изменились. Откройте новый план.")
		return
	}
	frozen := mihomoNodeCatalogClone(cat)
	service, err := dataplane.FrozenProbeService(plan.Routes[0])
	if err != nil {
		writeNodeApplyError(w, "MIHOMO_REVIEW_CHANGED", "Контрольный сценарий изменился.")
		return
	}
	binding := &mihomoNodeBinding{app: a, store: a.Store, node: node, before: cfg, catalog: frozen, plan: plan, service: service, profile: review.NetworkProfile}
	binding.self = binding
	ctx := context.WithValue(r.Context(), mihomoNodeBindingKey{}, binding)
	ctx = dataplane.WithReviewGuard(ctx, binding.current)
	execution, err := a.applyDataplane(ctx, plan, func() (func() error, error) {
		return binding.commit(ctx)
	})
	if err != nil {
		failure := classifyApplyExecutionFailure(err.Error(), execution.State)
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "MIHOMO_APPLY_FAILED", "live_applied": false, "error": failure.Message, "execution": execution, "failure": failure, "review_required": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "ok": true, "live_applied": true, "engine": "mihomo", "service_id": review.ServiceID, "node_id": id, "execution": execution, "pending_changes": a.pendingChanges()})
}
