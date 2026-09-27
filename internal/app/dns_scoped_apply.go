package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// References and a review fingerprint only; no provider credentials or cached PASS.
type scopedDNSApplySpec struct {
	Action    string `json:"action"`
	ProfileID string `json:"profile_id,omitempty"`
	Client    string `json:"client,omitempty"`
	Listener  string `json:"listener,omitempty"`
	Ingress   string `json:"ingress,omitempty"`
	Digest    string `json:"reviewed_digest,omitempty"`
}

type scopedDNSApplyRequest struct {
	ServiceID        string              `json:"service_id"`
	ExpectedRevision *uint64             `json:"expected_revision"`
	Spec             *scopedDNSApplySpec `json:"dns_apply"`
	Confirm          string              `json:"confirm,omitempty"`
	IdempotencyKey   string              `json:"idempotency_key,omitempty"`
}

func isScopedDNSApplyPath(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == "/api/v1/dns/scoped/preview" || r.URL.Path == "/api/v1/dns/scoped/apply")
}

func validScopedDNSApply(spec *scopedDNSApplySpec, reviewed bool) bool {
	if spec == nil || reviewed && !validJobHash(spec.Digest) || !reviewed && spec.Digest != "" {
		return false
	}
	if spec.Action == "remove" {
		return spec.ProfileID == "" && spec.Client == "" && spec.Listener == "" && spec.Ingress == ""
	}
	client, err := netip.ParseAddr(spec.Client)
	listener, listenerErr := netip.ParseAddrPort(spec.Listener)
	return spec.Action == "apply" && err == nil && client.Is4() && client.IsPrivate() && client.String() == spec.Client && listenerErr == nil && listener.Addr().Is4() && listener.Addr().IsPrivate() && listener.Addr() != client && listener.Port() >= 1024 && listener.Port() != 8787 && len(spec.Ingress) > 0 && len(spec.Ingress) <= 15 && strings.Trim(spec.Ingress, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.") == "" && spec.Ingress != "lo" && validScopedDNSID(spec.ProfileID)
}

func validScopedDNSID(id string) bool {
	return len(id) > 0 && len(id) <= 128 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.") == ""
}
func validDurableDNSApply(r serviceControlJobRequest) bool {
	return r.ExpectedRevision != nil && len(r.ServiceIDs) == 1 && validScopedDNSID(r.ServiceIDs[0]) && len(r.NodeIDs) == 0 && r.DNS == nil && r.NodeApply == nil && validScopedDNSApply(r.DNSApply, true)
}

func (a *App) scopedDNSApplyHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "Требуется вход в панель.", http.StatusUnauthorized)
		return
	}
	preview := r.URL.Path == "/api/v1/dns/scoped/preview"
	var q scopedDNSApplyRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(&struct{}{}) != io.EOF || q.ExpectedRevision == nil || !validScopedDNSID(q.ServiceID) || !validScopedDNSApply(q.Spec, !preview) || !preview && q.Confirm != "APPLY_SCOPED_DNS" || preview && (q.Confirm != "" || q.IdempotencyKey != "") {
		http.Error(w, "Проверьте сервис, DNS и подтверждение плана.", http.StatusBadRequest)
		return
	}
	if !preview {
		job, err := a.enqueueDurableServiceJob(r.Context(), serviceControlJobRequest{Kind: "dns-apply", ServiceIDs: []string{q.ServiceID}, ExpectedRevision: q.ExpectedRevision, DNSApply: q.Spec, IdempotencyKey: q.IdempotencyKey})
		if err != nil {
			a.writeDurableJobFailure(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job.presentation(), "persistent": true})
		return
	}
	release, err := a.Operations.Exclusive(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	plan, binding, err := a.reviewScopedDNSApply(ctx, q.ServiceID, *q.ExpectedRevision, *q.Spec)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "DNS_APPLY_CHANGED", "error": "План DNS недоступен. Сначала примените прямой маршрут для одного устройства и выберите DNS-профиль. Проверьте текущие маршруты и сеть.", "live_applied": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "review": binding.review, "plan": plan, "live_applied": false, "message": "Будет изменён DNS только выбранного устройства и сервиса. Действующие маршруты и ожидающие изменения сохраняются; приложения со своим DNS этим планом не охвачены."})
}

// Use only applied service targets. A DNS edit never commits an editor draft,
// widens a device scope, resolves a different AUTO target or enables a service.
func (a *App) reviewScopedDNSApply(ctx context.Context, id string, revision uint64, spec scopedDNSApplySpec) (dataplane.Plan, *applyReviewBinding, error) {
	fail := func(err error) (dataplane.Plan, *applyReviewBinding, error) { return dataplane.Plan{}, nil, err }
	if a.Store == nil || a.DNS == nil || a.Dataplane == nil || !a.Dataplane.Capable("dns-scoped") {
		return fail(errScopedDNSReview)
	}
	if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
		return fail(operationgate.ErrBusy)
	}
	cfg := a.Store.Get()
	if cfg.SafeMode || cfg.Revision != revision {
		return fail(dataplane.ErrReviewChanged)
	}
	previous, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || previous.State != "committed" || previous.Revision != cfg.AppliedRevision {
		return fail(dataplane.ErrReviewChanged)
	}
	change := &scopedDNSChange{Explicit: true}
	if spec.Action == "remove" {
		current := previous.DNS
		if previous.SuspendDNS {
			current, err = a.Dataplane.SuspendedDNS(previous)
			change.Discard = true
		}
		if err != nil || current == nil || len(current.Bindings) == 0 || current.Bindings[0].ServiceID != id {
			return fail(errScopedDNSReview)
		}
	} else {
		if cfg.ServiceControl.Stopped || previous.SuspendDNS {
			return fail(errScopedDNSReview)
		}
		var service catalog.Service
		for _, s := range a.catalogSnapshot().Services {
			if s.ID == id {
				service = s
				break
			}
		}
		state := cfg.AppliedServices[id]
		if service.ID == "" || !state.Enabled || state.Route != "direct" || !slices.Equal(state.Sources, []string{spec.Client + "/32"}) {
			return fail(errScopedDNSReview)
		}
		identity, err := a.DNS.ScopedProfileIdentity(spec.ProfileID)
		if err != nil {
			return fail(err)
		}
		probes := service.Probes
		if len(probes) == 0 && service.ProbeURL != "" {
			probes = []catalog.Probe{{ID: "web", Label: "Web", URL: service.ProbeURL, Required: true}}
		}
		policy := &dataplane.ScopedDNSPlan{Listener: spec.Listener, Ingress: spec.Ingress}
		for _, p := range probes {
			if p.Required && p.URL == service.ProbeURL {
				policy.Probe = p
				break
			}
		}
		for _, domain := range service.Domains {
			policy.Bindings = append(policy.Bindings, dataplane.ScopedDNSBinding{ServiceID: id, Client: spec.Client, Domain: domain, ProfileID: spec.ProfileID, ProfileDigest: identity})
		}
		change.Policy = policy
	}
	target := cfg
	target.Services = cfg.AppliedServices
	target.Revision = cfg.AppliedRevision
	plan, err := a.buildDataplanePlanWithDNS(target, a.nodeRouteOptions(), changeScopeNode, "", change)
	if err != nil || !plan.Ready {
		return fail(errors.Join(err, errScopedDNSReview))
	}
	if !sameDNSApplyRoutes(previous.Routes, plan.Routes) {
		return fail(errScopedDNSReview)
	}
	binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeNode, "")
	if err != nil {
		return fail(err)
	}
	// Bind the old journal too: a concurrent DNS-only operation may change it
	// without changing the main settings revision.
	binding.review.Digest = applyReviewHash(struct {
		Review   string
		Previous dataplane.Plan
	}{binding.review.Digest, previous})
	return plan, binding, nil
}

func sameDNSApplyRoutes(left, right []dataplane.Route) bool {
	if len(left) != len(right) {
		return false
	}
	old := map[string]dataplane.Route{}
	for _, r := range left {
		r.AppliedRoute = ""
		old[r.ServiceID] = r
	}
	for _, r := range right {
		r.AppliedRoute = ""
		if applyReviewHash(old[r.ServiceID]) != applyReviewHash(r) {
			return false
		}
	}
	return true
}

func (a *App) runDurableDNSApply(ctx context.Context, r serviceControlJobRequest) (serviceRuntimeOutcome, error) {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return serviceRuntimeOutcome{}, err
	}
	defer func() { release(); a.wakePanelSnapshot() }()
	if !validDurableDNSApply(r) {
		return serviceRuntimeOutcome{Code: "DNS_APPLY_CHANGED"}, nil
	}
	plan, binding, err := a.reviewScopedDNSApply(ctx, r.ServiceIDs[0], *r.ExpectedRevision, *r.DNSApply)
	if err != nil || binding.review.Digest != r.DNSApply.Digest {
		return serviceRuntimeOutcome{Code: "DNS_APPLY_CHANGED"}, nil
	}
	previous, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		return serviceRuntimeOutcome{Code: "DNS_APPLY_CHANGED"}, nil
	}
	ctx = dataplane.WithReviewGuard(ctx, func(ctx context.Context) error {
		if err := binding.guard(a, ctx); err != nil {
			return err
		}
		current, exists, err := a.Dataplane.Committed()
		if err != nil || !exists || !sameNodeRecoveryPlan(current, previous) {
			return dataplane.ErrReviewChanged
		}
		return nil
	})
	execution, err := a.applyDataplane(ctx, plan, nil)
	if err != nil {
		return serviceRuntimeOutcome{Code: "DNS_APPLY_FAILED", Execution: &execution}, nil
	}
	a.wakeReconciler()
	return serviceRuntimeOutcome{LiveApplied: true, Execution: &execution}, nil
}

func validDNSApplyCode(code string) bool {
	return slices.Contains([]string{"", "DNS_APPLY_CHANGED", "DNS_APPLY_FAILED"}, code)
}
func dnsApplyJobMessage(j durableServiceJob) string {
	switch j.State {
	case "queued":
		return "Применение DNS сохранено на роутере. Браузер можно закрыть."
	case "running":
		return "Проверяем и применяем DNS для выбранного устройства. При ошибке завершим откат."
	case "completed":
		if j.Request.DNSApply.Action == "remove" {
			return "Отдельная привязка DNS удалена. Маршруты сервисов сохранены."
		}
		return "DNS применён и проверен с роутера. Проверьте сервис на выбранном устройстве."
	case "canceling":
		return "Отмена сохранена; ожидаем завершения отката DNS."
	case "canceled":
		return "Применение DNS отменено. Текущее состояние показано отдельно."
	}
	if j.CleanupOutcome == "unverified" {
		return "Откат DNS требует проверки. Следующие изменения приостановлены; откройте журнал."
	}
	if j.DNSApplyCode == "DNS_APPLY_CHANGED" {
		return "План DNS изменился или приложение перезапущено. Откройте новый план; старое действие не повторялось."
	}
	return "DNS не применён. Проверьте текущий маршрут и журнал транзакции."
}
