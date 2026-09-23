package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

const changeScopeNode changeScope = "node"
const nodeReviewTTL = 2 * time.Minute
const maxNodeReviews = 64
const maxNodeScopeSources = 128

type nodeScopeSelection struct {
	Mode    string   `json:"mode"`
	Sources []string `json:"sources,omitempty"`
}

type nodeScopeView struct {
	Mode        string   `json:"mode"`
	Sources     []string `json:"sources"`
	SourceCount int      `json:"source_count"`
	Summary     string   `json:"summary"`
}

func nodeScopePresentation(sources []string) nodeScopeView {
	view := nodeScopeView{Mode: "all", Sources: append([]string{}, sources...), SourceCount: len(sources), Summary: "Все устройства локальной сети"}
	if len(sources) > 0 {
		view.Mode = "selected"
		view.Summary = fmt.Sprintf("Выбрано адресов или сетей: %d", len(sources))
	}
	return view
}

func resolveNodeScope(cfg config.Config, serviceID string, selection *nodeScopeSelection) (string, []string, error) {
	mode := "applied"
	if selection != nil {
		mode = selection.Mode
		if mode != "selected" && len(selection.Sources) != 0 {
			return "", nil, errors.New("sources require selected scope")
		}
	}
	var sources []string
	switch mode {
	case "applied":
		sources = config.AppliedSources(cfg, serviceID)
	case "draft":
		sources = cfg.Services[serviceID].Sources
	case "all":
	case "selected":
		if len(selection.Sources) == 0 || len(selection.Sources) > maxNodeScopeSources {
			return "", nil, errors.New("invalid selected scope size")
		}
		sources = selection.Sources
	default:
		return "", nil, errors.New("invalid node scope mode")
	}
	normalized, err := config.NormalizeSources(sources)
	if err != nil || mode == "selected" && len(normalized) == 0 {
		return "", nil, errors.New("invalid node scope addresses")
	}
	return mode, normalized, nil
}

type nodeRouteReview struct {
	Token          string    `json:"review_token"`
	Digest         string    `json:"reviewed_digest"`
	Revision       uint64    `json:"revision"`
	Generation     uint64    `json:"generation"`
	NodeID         string    `json:"node_id"`
	ServiceID      string    `json:"service_id"`
	NetworkProfile string    `json:"network_profile"`
	ExpiresAt      time.Time `json:"expires_at"`
	ScopeSelection string    `json:"scope_selection"`
	scopeSources   []string
	intentHash     string // Private immutable config/definition binding from preview.
	owner          [32]byte
}

type nodeRouteReviewStore struct {
	mu      sync.Mutex
	reviews map[string]nodeRouteReview
	// Tests replace only host inventory; proof still comes from the real Store.
	options func() []routecatalog.Option
}

func (a *App) nodeRouteOptions() []routecatalog.Option {
	if a.nodeReviews.options != nil {
		return a.nodeReviews.options()
	}
	return a.routeOptionsSnapshot()
}

func nodeReviewOwner(r *http.Request) [32]byte {
	cookie, _ := r.Cookie("razvilka_session")
	session := ""
	if cookie != nil {
		session = cookie.Value
	}
	return sha256.Sum256([]byte(session + "\x00" + r.Header.Get("Authorization")))
}

func (s *nodeRouteReviewStore) put(review nodeRouteReview, now time.Time) (nodeRouteReview, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return review, err
	}
	review.Token = hex.EncodeToString(token[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reviews == nil {
		s.reviews = make(map[string]nodeRouteReview)
	}
	for key, existing := range s.reviews {
		if !now.Before(existing.ExpiresAt) {
			delete(s.reviews, key)
		}
	}
	if len(s.reviews) >= maxNodeReviews {
		var oldest string
		for key, existing := range s.reviews {
			if oldest == "" || existing.ExpiresAt.Before(s.reviews[oldest].ExpiresAt) {
				oldest = key
			}
		}
		delete(s.reviews, oldest)
	}
	s.reviews[review.Token] = review
	return review, nil
}

func (s *nodeRouteReviewStore) take(token string, owner [32]byte, now time.Time) (nodeRouteReview, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	review, ok := s.reviews[token]
	if !ok || review.owner != owner {
		return nodeRouteReview{}, false
	}
	delete(s.reviews, token) // Every authorized attempt consumes its review.
	return review, now.Before(review.ExpiresAt)
}

// This is a hypothetical config only. A preview never writes a service draft.
func nodeRouteConfig(cfg config.Config, id, nodeID string) config.Config {
	return nodeRouteConfigForScope(cfg, id, nodeID, cfg.AppliedServices[id].Sources)
}

func nodeRouteConfigForScope(cfg config.Config, id, nodeID string, sources []string) config.Config {
	services := make(map[string]config.ServiceState, len(cfg.AppliedServices)+1)
	for key, value := range cfg.AppliedServices {
		value.Sources = append([]string(nil), value.Sources...)
		services[key] = value
	}
	selected := services[id]
	selected.Enabled, selected.Mode, selected.Route = true, "sing-box:"+nodeID, "sing-box:"+nodeID
	selected.Sources = append([]string(nil), sources...)
	services[id] = selected
	cfg.Services = services
	cfg.Revision++ // Matches the single atomic routing commit after health.
	return cfg
}

func (a *App) nodeReviewProof(ctx context.Context, review nodeRouteReview, revision uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(review.ExpiresAt) || a.Store.Get().Revision != revision {
		return dataplane.ErrReviewChanged
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || snapshot.Generation != review.Generation {
		return dataplane.ErrReviewChanged
	}
	_, err = a.Nodes.ResolveRoute(ctx, review.NodeID, review.ServiceID, review.NetworkProfile, "", time.Time{}, time.Now())
	if err != nil {
		return dataplane.ErrReviewChanged
	}
	return ctx.Err()
}

func (a *App) nodeRoutePreview(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Store == nil || a.Dataplane == nil {
		writeNodeApplyError(w, "NODE_APPLY_UNAVAILABLE", "Применение узлов сейчас недоступно.")
		return
	}
	var request struct {
		ServiceID        string              `json:"service_id"`
		Scope            *nodeScopeSelection `json:"scope,omitempty"`
		ExpectedRevision *uint64             `json:"expected_revision,omitempty"`
	}
	// A bounded list of 128 full IPv6 prefixes may exceed the ordinary 4 KiB
	// node mutation limit. Keep the same strict JSON contract at 16 KiB here.
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "некорректный запрос просмотра узла", http.StatusBadRequest)
		return
	}
	name := ""
	var reviewedServices []catalog.Service
	for _, service := range a.catalogSnapshot().Services {
		if service.ID == request.ServiceID && serviceHasNodeProbe(service) {
			name = service.Name
			reviewedServices = append(reviewedServices, service)
			break
		}
	}
	if name == "" {
		writeNodeApplyError(w, "NODE_SERVICE_UNAVAILABLE", "Выберите сервис с доступным контрольным сценарием.")
		return
	}
	profile, err := a.freshNetworkProfile(r.Context())
	if err != nil {
		writeNodeNetworkError(w)
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision == ^uint64(0) || request.ExpectedRevision != nil && *request.ExpectedRevision != cfg.Revision {
		writeNodeApplyError(w, "NODE_REVIEW_CHANGED", "Обновите настройки перед применением.")
		return
	}
	scopeMode, scopeSources, err := resolveNodeScope(cfg, request.ServiceID, request.Scope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "NODE_SCOPE_INVALID", "error": "Выберите всю сеть, действующую область, черновик или от 1 до 128 корректных адресов устройств.", "working_routes_changed": false})
		return
	}
	snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
	if err != nil {
		writeNodeError(w, err)
		return
	}
	var node nodestore.Node
	for _, candidate := range snapshot.Nodes {
		if candidate.ID == id {
			node = candidate
			break
		}
	}
	if node.ID == "" {
		writeNodeError(w, nodestore.ErrNotFound)
		return
	}
	if _, err = a.Nodes.ResolveRoute(r.Context(), id, request.ServiceID, profile, "", time.Time{}, time.Now()); err != nil {
		writeNodeError(w, err)
		return
	}
	review := nodeRouteReview{Revision: cfg.Revision, Generation: snapshot.Generation, NodeID: id, ServiceID: request.ServiceID, NetworkProfile: profile, ExpiresAt: time.Now().Add(nodeReviewTTL), ScopeSelection: scopeMode, scopeSources: append([]string(nil), scopeSources...), owner: nodeReviewOwner(r), intentHash: durableServiceIntentHash(cfg, reviewedServices)}
	for _, check := range node.Health.History {
		if check.ServiceID == request.ServiceID && check.NetworkProfile == profile && check.RoutePathID == "sing-box:"+id {
			if check.ExpiresAt.Before(review.ExpiresAt) {
				review.ExpiresAt = check.ExpiresAt
			}
			break
		}
	}
	plan, err := a.buildDataplanePlanForScope(nodeRouteConfigForScope(cfg, request.ServiceID, id, review.scopeSources), a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil {
		writeNodePlanFailure(w, err)
		return
	}
	if plan.NetworkProfileID != profile || a.nodeReviewProof(r.Context(), review, cfg.Revision) != nil {
		writeNodeApplyError(w, "NODE_REVIEW_CHANGED", "Во время просмотра изменились настройки, узлы или срок проверки. Откройте новый план.")
		return
	}
	review.Digest = plan.Digest
	ready := plan.Ready && !cfg.SafeMode
	if ready {
		review, err = a.nodeReviews.put(review, time.Now())
		if err != nil {
			writeNodeApplyError(w, "NODE_APPLY_UNAVAILABLE", "Не удалось подготовить подтверждение. Повторите просмотр.")
			return
		}
	}
	appliedSources, draftSources := cfg.AppliedServices[request.ServiceID].Sources, cfg.Services[request.ServiceID].Sources
	draftPending := !stringSlicesEqual(appliedSources, draftSources)
	scopeNotice := "Применится действующая область устройств. Остальные черновики сохранятся."
	if scopeMode == "applied" && draftPending {
		scopeNotice = "Применится действующая область устройств. Изменённый список устройств останется в черновике."
	} else if scopeMode == "draft" {
		scopeNotice = "Будет применён список устройств из черновика этого сервиса. Остальные черновики сохранятся."
	} else if scopeMode != "applied" {
		scopeNotice = "Выбранная область заменит действующую область и черновик устройств этого сервиса. Остальные черновики сохранятся."
	}
	_, appliedPresent := cfg.AppliedServices[request.ServiceID]
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "ready": ready, "safe_mode": cfg.SafeMode, "review": review, "transaction": plan,
		"service_name": name, "node_name": node.Name, "before_route": selectedRoute(cfg.AppliedServices[request.ServiceID]),
		"applied_scope": nodeScopePresentation(appliedSources), "draft_scope": nodeScopePresentation(draftSources), "effective_scope": nodeScopePresentation(scopeSources),
		"applied_scope_present": appliedPresent, "scope_selection": scopeMode, "scope_changed": !stringSlicesEqual(appliedSources, scopeSources),
		"draft_scope_pending": draftPending, "draft_scope_deferred": scopeMode == "applied" && draftPending, "scope_notice": scopeNotice,
		"note":                   "Будет включён выбранный сервис через этот узел. " + scopeNotice,
		"verification":           "Перед переключением выполняется изолированная проверка. Ошибка после переключения запускает автоматический откат.",
		"working_routes_changed": false,
	})
}

type nodeApplyRequest struct {
	Token          string `json:"review_token"`
	Digest         string `json:"reviewed_digest"`
	Revision       uint64 `json:"revision"`
	Generation     uint64 `json:"generation"`
	ServiceID      string `json:"service_id"`
	Confirm        string `json:"confirm"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (a *App) nodeRouteApply(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Store == nil || a.Dataplane == nil {
		writeNodeApplyError(w, "NODE_APPLY_UNAVAILABLE", "Применение узлов сейчас недоступно.")
		return
	}
	var request nodeApplyRequest
	if !decodeNodeMutation(w, r, &request) {
		return
	}
	if request.Confirm != "APPLY_NODE_ROUTE" {
		writeNodeApplyError(w, "NODE_REVIEW_REQUIRED", "Просмотрите маршрут и явно подтвердите применение.")
		return
	}
	if request.IdempotencyKey != "" {
		job, err := a.enqueueDurableServiceJob(r.Context(), serviceControlJobRequest{
			Kind: "node-apply", ServiceIDs: []string{request.ServiceID}, NodeIDs: []string{id},
			ExpectedRevision: &request.Revision, IdempotencyKey: request.IdempotencyKey,
			NodeApply:       &nodeApplyJobSpec{Digest: request.Digest, Generation: request.Generation},
			nodeReviewToken: request.Token, nodeReviewOwner: nodeReviewOwner(r),
		})
		if err != nil {
			a.writeDurableJobFailure(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job.presentation(), "persistent": true})
		return
	}
	// Legacy callers retain synchronous behavior; both paths own their admission.
	release, err := a.Operations.Exclusive(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	review, ok := a.nodeReviews.take(request.Token, nodeReviewOwner(r), time.Now())
	if !ok || review.NodeID != id || review.ServiceID != request.ServiceID || review.Digest != request.Digest || review.Revision != request.Revision || review.Generation != request.Generation {
		writeNodeApplyError(w, "NODE_REVIEW_CHANGED", "Подтверждение устарело или относится к другому выбору. Откройте новый план.")
		return
	}
	outcome := a.executeNodeRoute(r.Context(), review)
	if outcome.Code != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": outcome.Code, "live_applied": false, "error": outcome.Message, "failure": outcome.Failure, "execution": outcome.Execution, "review_required": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "live_applied": true, "service_id": review.ServiceID, "node_id": id, "execution": outcome.Execution, "pending_changes": a.pendingChanges(), "note": "Сервис включён через выбранный узел. Рабочий маршрут прошёл контрольную проверку."})
}

// Caller owns admission until the existing transaction's rollback/cleanup joins.
func (a *App) executeNodeRoute(parent context.Context, review nodeRouteReview) serviceRuntimeOutcome {
	fail := func(code, message string) serviceRuntimeOutcome {
		return serviceRuntimeOutcome{Code: code, Message: message}
	}
	cfg := a.Store.Get()
	profile, err := a.freshNetworkProfile(parent)
	if err != nil || profile != review.NetworkProfile {
		return fail("NODE_NETWORK_CHANGED", "Сеть изменилась. Проверьте подключение и откройте новый план.")
	}
	if cfg.SafeMode || a.nodeReviewProof(parent, review, cfg.Revision) != nil || cfg.Revision != review.Revision {
		return fail("NODE_REVIEW_CHANGED", "Настройки, узлы или срок проверки изменились. Проверьте узел и откройте новый план.")
	}
	plan, err := a.buildDataplanePlanForScope(nodeRouteConfigForScope(cfg, review.ServiceID, review.NodeID, review.scopeSources), a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || !plan.Ready || plan.Digest != review.Digest || plan.NetworkProfileID != review.NetworkProfile {
		var dependency *routePlanDependencyError
		if errors.As(err, &dependency) {
			return fail("NODE_ROUTE_DEPENDENCY", dependency.Error())
		}
		return fail("NODE_REVIEW_CHANGED", "Состав или условия маршрута изменились. Откройте новый план.")
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	defer cancel()
	committed := false
	guard := func(ctx context.Context) error {
		revision := review.Revision
		if committed {
			revision++
		}
		return a.nodeReviewProof(ctx, review, revision)
	}
	ctx = dataplane.WithReviewGuard(ctx, guard)
	execution, err := a.applyDataplane(ctx, plan, func() (func() error, error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		var undo func() error
		var err error
		if review.ScopeSelection == "applied" {
			undo, err = a.Store.ApplyNodeRouteWithRollback(review.ServiceID, "sing-box:"+review.NodeID, review.Revision)
		} else {
			undo, err = a.Store.ApplyNodeRouteScopeWithRollback(review.ServiceID, "sing-box:"+review.NodeID, review.scopeSources, review.Revision)
		}
		if errors.Is(err, config.ErrRevisionChanged) {
			return nil, dataplane.ErrReviewChanged
		}
		if err == nil {
			committed = true
		}
		return undo, err
	})
	if err != nil {
		failure := classifyApplyExecutionFailure(err.Error(), execution.State)
		return serviceRuntimeOutcome{Code: "NODE_APPLY_FAILED", Message: failure.Message, Failure: &failure, Execution: &execution}
	}
	return serviceRuntimeOutcome{LiveApplied: true, Execution: &execution}
}

func writeNodeApplyError(w http.ResponseWriter, code, message string) {
	writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": code, "error": message, "working_routes_changed": false, "live_applied": false, "review_required": true})
}
