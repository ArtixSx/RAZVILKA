package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodecleanup"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

var cleanupNodeID = regexp.MustCompile(`^node-[a-f0-9]{64}$`)

type nodeCleanupRequest struct {
	NodeIDs        []string `json:"node_ids"`
	Generation     uint64   `json:"generation"`
	Mode           string   `json:"mode"`
	ServiceID      string   `json:"service_id"`
	NetworkProfile string   `json:"network_profile"`
	Preview        bool     `json:"preview"`
	Confirm        string   `json:"confirm"`
	Review         string   `json:"review,omitempty"`
}
type nodeCleanupItem struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Preview and commit use the same exclusive operation admission. Each commit
// repeats all reference/health checks, and a changed registry rejects the batch.
// Individual deletions are atomic; batch errors report the partial outcome.
func (a *App) nodeCleanup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var q nodeCleanupRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&q) != nil || dec.Decode(&struct{}{}) != io.EOF || !validNodeCleanupRequest(q) {
		writeJSON(w, 400, map[string]any{"error": "Выберите от 1 до 64 узлов и подтвердите удаление."})
		return
	}
	seen := map[string]bool{}
	for _, id := range q.NodeIDs {
		if !cleanupNodeID.MatchString(id) || seen[id] {
			writeJSON(w, 400, map[string]any{"error": "Некорректный состав узлов."})
			return
		}
		seen[id] = true
	}
	if a.Nodes == nil || a.Store == nil {
		writeJSON(w, 503, map[string]any{"error": "Нельзя проверить ссылки на узлы: хранилище недоступно."})
		return
	}
	release, err := a.privateRestoreAdmission(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	now := time.Now()
	snapshot, err := a.Nodes.Snapshot(r.Context(), now)
	if err != nil {
		writeNodeError(w, err)
		return
	}
	if snapshot.Generation != q.Generation {
		writeJSON(w, 409, map[string]any{"error": "Каталог изменился. Обновите выборку и повторите предпросмотр.", "not_started": true})
		return
	}
	if q.Mode == "all-vless" {
		for _, n := range snapshot.Nodes {
			if strings.EqualFold(strings.TrimSpace(n.Protocol), "vless") {
				q.NodeIDs = append(q.NodeIDs, n.ID)
			}
		}
	}
	protected, err := a.protectedCleanupNodes(r.Context(), snapshot)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "Владение или состояние восстановления не подтверждено. Узлы сохранены."})
		return
	}
	profile := ""
	if q.Mode == "failed" {
		profile, err = a.freshNetworkProfile(r.Context())
		if err != nil || profile != q.NetworkProfile || q.ServiceID == "" {
			writeNodeNetworkError(w)
			return
		}
		if _, ok := a.autonomyService(q.ServiceID); !ok {
			writeJSON(w, 400, map[string]any{"error": "Сервис не найден."})
			return
		}
	}
	control := recentCleanupControl(snapshot, profile, now)
	nodes := map[string]nodestore.Node{}
	for _, n := range snapshot.Nodes {
		nodes[n.ID] = n
	}
	candidates := []nodeCleanupItem{}
	skipped := []nodeCleanupItem{}
	for _, id := range q.NodeIDs {
		n, ok := nodes[id]
		reason := protected[id]
		if !ok {
			reason = "Запись уже отсутствует."
		}
		if reason == "" && q.Mode == "failed" && !nodecleanup.Eligible(id, q.ServiceID, profile, cleanupChecks(n), now, control) {
			reason = "Нет двух свежих подтверждённых отказов узла. Ошибки отдельного сервиса и неоднозначные результаты не удаляются."
		}
		item := nodeCleanupItem{NodeID: id, Name: n.Name, Reason: reason}
		if reason != "" {
			skipped = append(skipped, item)
		} else {
			candidates = append(candidates, item)
		}
	}
	review := applyReviewHash(struct {
		Generation          uint64
		Mode, Catalogue     string
		Candidates, Skipped []nodeCleanupItem
	}{snapshot.Generation, q.Mode, applyReviewHash(snapshot.Nodes), candidates, skipped})
	if q.Preview {
		writeJSON(w, 200, map[string]any{"preview": true, "generation": snapshot.Generation, "candidates": candidates, "skipped": skipped, "working_routes_changed": false, "scope": q.Mode, "review": review, "matched": len(q.NodeIDs)})
		return
	}
	if q.Mode == "all-vless" {
		if q.Review != review {
			writeJSON(w, 409, map[string]any{"error": "Состав удаления изменился. Повторите предпросмотр; узлы сохранены.", "not_started": true})
			return
		}
		ids := make([]string, 0, len(candidates))
		for _, n := range candidates {
			ids = append(ids, n.NodeID)
		}
		if len(ids) > 0 {
			if _, err := a.Nodes.DeleteBatch(r.Context(), ids, snapshot.Generation, time.Now()); err != nil {
				writeJSON(w, 409, map[string]any{"error": "Каталог изменился или запись удаления не подтверждена. Обновите состояние и повторите предпросмотр.", "working_routes_changed": false})
				return
			}
		}
		writeJSON(w, 200, map[string]any{"complete": true, "deleted": ids, "skipped": skipped, "working_routes_changed": false, "note": "Удалены локальные неиспользуемые VLESS. Другие протоколы и маршруты сохранены. Подписка может импортировать эти ссылки снова."})
		return
	}
	deleted := []string{}
	failure := ""
	for _, item := range candidates {
		if r.Context().Err() != nil {
			failure = "Удаление отменено; выполненные записи перечислены отдельно."
			break
		}
		if q.Mode == "failed" {
			current, e := a.freshNetworkProfile(r.Context())
			if e != nil || current != profile {
				failure = "Сеть изменилась. Оставшиеся узлы сохранены."
				break
			}
		}
		if _, err = a.Nodes.Delete(r.Context(), item.NodeID, time.Now()); err != nil {
			if errors.Is(err, nodestore.ErrInUse) {
				item.Reason = "Узел используется группой."
				skipped = append(skipped, item)
				continue
			}
			failure = "Запись удаления не подтверждена. Обновите каталог; оставшиеся узлы сохранены."
			break
		}
		deleted = append(deleted, item.NodeID)
	}
	// A 200 response with complete=false is an explicit partial result, not a
	// silent blanket success. This keeps already completed operations visible.
	writeJSON(w, 200, map[string]any{"complete": failure == "", "deleted": deleted, "skipped": skipped, "error": failure, "working_routes_changed": false,
		"note": "Удалены только локальные неиспользуемые записи. Включённая подписка может снова прислать их при синхронизации."})
}

func cleanupChecks(n nodestore.Node) []nodecleanup.Check {
	checks := []nodecleanup.Check{}
	for _, c := range n.Health.History {
		checks = append(checks, nodecleanup.Check{ServiceID: c.ServiceID, Network: c.NetworkProfile, Route: c.RoutePathID, Verdict: c.Verdict, Level: c.TestLevel, Code: c.ErrorCode, State: c.State, DirectLeak: c.DirectLeak, At: c.CheckedAt, Until: c.ExpiresAt})
	}
	if len(checks) == 0 && !n.Health.CheckedAt.IsZero() {
		c := n.Health
		checks = append(checks, nodecleanup.Check{ServiceID: c.ServiceID, Network: c.NetworkProfile, Route: c.RoutePathID, Verdict: c.Verdict, Level: c.TestLevel, Code: c.ErrorCode, State: c.State, DirectLeak: c.DirectLeak, At: c.CheckedAt, Until: c.ExpiresAt})
	}
	return checks
}
func recentCleanupControl(s nodestore.Snapshot, profile string, now time.Time) bool {
	for _, n := range s.Nodes {
		// Consider the latest check only: an old PASS cannot survive a later outage.
		cs := cleanupChecks(n)
		var latest nodecleanup.Check
		for _, c := range cs {
			if c.Network == profile && c.At.After(latest.At) {
				latest = c
			}
		}
		if !n.Disabled && n.State != "expired" && latest.Route == "sing-box:"+n.ID && latest.Verdict == "PASS" && latest.Level == "service" && latest.State == "available" && !latest.DirectLeak &&
			!latest.At.After(now) && latest.At.After(now.Add(-2*time.Minute)) && latest.Until.After(now) {
			return true
		}
	}
	return false
}

func (a *App) protectedCleanupNodes(ctx context.Context, snapshot nodestore.Snapshot) (map[string]string, error) {
	refs := map[string]string{}
	add := func(id, why string) {
		if cleanupNodeID.MatchString(id) {
			refs[id] = why
		}
	}
	route := func(value, why string) {
		if strings.HasPrefix(value, "sing-box:node-") {
			add(strings.TrimPrefix(value, "sing-box:"), why)
		}
	}
	for _, g := range snapshot.Groups {
		for _, id := range g.NodeIDs {
			add(id, "Узел включён в группу «"+g.Name+"».")
		}
	}
	if a.Store != nil {
		cfg := a.Store.Get()
		for _, states := range []map[string]config.ServiceState{cfg.Services, cfg.AppliedServices, cfg.ServiceControl.SuspendedServices} {
			for _, s := range states {
				route(selectedRoute(s), "Узел выбран, применён или сохранён для восстановления сервиса.")
			}
		}
		for _, r := range cfg.ServiceControl.SuspendedRoutes {
			route(r, "Маршрут приостановлен, но должен восстановиться.")
		}
		for _, p := range cfg.ServicePolicies {
			add(p.PinnedNodeID, "Узел закреплён политикой.")
			for _, id := range p.AllowedNodeIDs {
				add(id, "Узел находится в разрешённом резерве политики.")
			}
		}
		if err := a.loadAutonomy(ctx); err != nil {
			return nil, err
		}
	}
	a.autonomy.mu.Lock()
	if a.autonomy.blocked {
		a.autonomy.mu.Unlock()
		return nil, errors.New("autonomy recovery is blocked")
	}
	for _, s := range a.autonomy.doc.Services {
		route(s.ExpectedRoute, "Узел закреплён автономным намерением.")
	}
	for _, r := range a.autonomy.doc.Runtime {
		for _, id := range r.Reserves {
			add(id, "Узел нужен резерву Автопилота.")
		}
	}
	a.autonomy.mu.Unlock()
	if a.Dataplane != nil {
		st, err := a.Dataplane.Status()
		if err != nil {
			return nil, err
		}
		for _, p := range []*dataplane.Plan{st.Plan, st.CommittedPlan} {
			if p != nil {
				for _, r := range p.Routes {
					route(r.Selected, "Узел нужен текущему плану или откату.")
					route(r.Resolved, "Узел нужен текущему плану или откату.")
				}
			}
		}
	}
	return refs, nil
}
