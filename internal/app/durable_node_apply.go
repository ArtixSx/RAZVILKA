package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var errNodeJobReview = errors.New("node apply review is unavailable or changed")

// A durable intent has no bearer token, node credential or replayable plan.
type nodeApplyJobSpec struct {
	Digest     string `json:"digest"`
	Generation uint64 `json:"generation"`
}

type durableNodeReview struct {
	NetworkProfile string    `json:"network_profile"`
	ExpiresAt      time.Time `json:"expires_at"`
	ScopeSelection string    `json:"scope_selection"`
	Sources        []string  `json:"sources"`
}

func isNodeApplyPath(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && strings.HasSuffix(r.URL.Path, "/apply")
}

func validDurableNodeApply(r serviceControlJobRequest) bool {
	return r.ExpectedRevision != nil && len(r.ServiceIDs) == 1 && len(r.NodeIDs) == 1 &&
		r.DNS == nil && r.NodeApply != nil && validJobHash(r.NodeApply.Digest) && r.NodeApply.Generation > 0 &&
		len(r.ServiceIDs[0]) > 0 && len(r.ServiceIDs[0]) <= 128 && strings.Trim(r.ServiceIDs[0], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") == "" &&
		strings.HasPrefix(r.NodeIDs[0], "node-") && validJobHash(strings.TrimPrefix(r.NodeIDs[0], "node-"))
}

func validDurableNodeReview(j durableServiceJob) bool {
	if j.Request.Kind != "node-apply" {
		return j.NodeReview == nil && j.NodeCode == ""
	}
	v := j.NodeReview
	if v == nil || !validDurableNodeApply(j.Request) || !validNodeJobCode(j.NodeCode) ||
		len(v.NetworkProfile) != 16 || !strings.HasPrefix(v.NetworkProfile, "wan-") || strings.Trim(v.NetworkProfile[4:], "0123456789abcdef") != "" ||
		v.ExpiresAt.IsZero() || v.ExpiresAt.After(j.CreatedAt.Add(nodeReviewTTL)) ||
		!slices.Contains([]string{"applied", "draft", "selected", "all"}, v.ScopeSelection) || len(v.Sources) > maxNodeScopeSources || v.ScopeSelection == "all" && len(v.Sources) != 0 || v.ScopeSelection == "selected" && len(v.Sources) == 0 {
		return false
	}
	sources, err := config.NormalizeSources(v.Sources)
	return err == nil && slices.Equal(sources, v.Sources)
}

// Called under exclusive admission. The token is consumed only after the
// accepted intent is durable; storage failure leaves the reviewed action usable.
func (a *App) prepareDurableNodeApply(ctx context.Context, r serviceControlJobRequest, token string, owner [32]byte) (*durableNodeReview, error) {
	if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
		return nil, operationgate.ErrBusy
	}
	a.nodeReviews.mu.Lock()
	review, ok := a.nodeReviews.reviews[token]
	a.nodeReviews.mu.Unlock()
	if !ok || review.owner != owner || review.NodeID != r.NodeIDs[0] || review.ServiceID != r.ServiceIDs[0] || review.Revision != *r.ExpectedRevision || review.Generation != r.NodeApply.Generation || review.Digest != r.NodeApply.Digest || a.nodeReviewProof(ctx, review, review.Revision) != nil {
		return nil, errNodeJobReview
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil || profile != review.NetworkProfile {
		return nil, errNodeJobReview
	}
	return &durableNodeReview{NetworkProfile: review.NetworkProfile, ExpiresAt: review.ExpiresAt, ScopeSelection: review.ScopeSelection, Sources: slices.Clone(review.scopeSources)}, nil
}

func (a *App) runDurableNodeApply(ctx context.Context, r serviceControlJobRequest, saved *durableNodeReview) (serviceRuntimeOutcome, error) {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return serviceRuntimeOutcome{}, err
	}
	defer func() { release(); a.wakePanelSnapshot() }()
	if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
		return serviceRuntimeOutcome{}, operationgate.ErrBusy
	}
	if err := ctx.Err(); err != nil {
		return serviceRuntimeOutcome{}, err
	}
	if a.Store == nil || a.Dataplane == nil || a.Nodes == nil || saved == nil || !validDurableNodeApply(r) {
		return serviceRuntimeOutcome{Code: "NODE_APPLY_UNAVAILABLE"}, nil
	}
	cfg := a.Store.Get()
	services := []catalog.Service{}
	for _, s := range a.catalogSnapshot().Services {
		if s.ID == r.ServiceIDs[0] {
			services = append(services, s)
		}
	}
	if cfg.Revision != *r.ExpectedRevision || len(services) != 1 || durableServiceIntentHash(cfg, services) != r.intentHash {
		return serviceRuntimeOutcome{Code: "NODE_REVIEW_CHANGED"}, nil
	}
	return a.executeNodeRoute(ctx, nodeRouteReview{Revision: *r.ExpectedRevision, Generation: r.NodeApply.Generation,
		NodeID: r.NodeIDs[0], ServiceID: r.ServiceIDs[0], Digest: r.NodeApply.Digest,
		NetworkProfile: saved.NetworkProfile, ExpiresAt: saved.ExpiresAt, ScopeSelection: saved.ScopeSelection, scopeSources: slices.Clone(saved.Sources)}), nil
}

func validNodeJobCode(code string) bool {
	return slices.Contains([]string{"", "NODE_APPLY_UNAVAILABLE", "NODE_REVIEW_CHANGED", "NODE_NETWORK_CHANGED", "NODE_ROUTE_DEPENDENCY", "NODE_APPLY_FAILED"}, code)
}

func nodeApplyJobMessage(j durableServiceJob) string {
	switch j.State {
	case "queued":
		return "Применение подключения сохранено на роутере. Браузер можно закрыть."
	case "running":
		return "Проверяем и применяем подключение. При ошибке завершим откат."
	case "canceling":
		return "Ожидаем завершения отмены и очистки."
	case "completed":
		return "Подключение применено и прошло проверку. Проверьте сервис на выбранном устройстве."
	case "canceled":
		return "Применение отменено. Текущее состояние показано отдельно."
	}
	if j.CleanupOutcome == "unverified" {
		return "Возврат маршрутов требует проверки. Следующие изменения приостановлены; откройте журнал."
	}
	if j.NodeCode == "NODE_ROUTE_DEPENDENCY" {
		return "Один из действующих маршрутов требует проверки. Откройте новый план: он покажет сервис, который мешает применению."
	}
	if j.NodeCode == "NODE_APPLY_FAILED" {
		return "Подключение не применено. Откройте журнал транзакции и проверьте текущее состояние."
	}
	return "Условия просмотра изменились или приложение перезапущено. Проверьте подключение и откройте новый план. Старое применение повторно не выполнялось."
}
