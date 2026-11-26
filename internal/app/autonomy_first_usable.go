package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodequality"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

const homeServiceCheckedMessage = "Сервис ответил через узел Xray при отдельной проверке. Узел сохранён в резерве. Эта версия не поддерживает пересылку через Xray для всей домашней сети."
const homeServiceCheckedState = "service-checked-lan-unavailable"

var errAutonomySearchBudget = errors.New("autonomy apply budget exhausted")
var errAutonomySearchPersistence = errors.New("autonomy traversal could not be persisted")

// autonomySearchServiceRefusal reports a consumable refusal by the service
// itself: the older ServiceFailure class, or the shared definite-refusal class
// after a measured direct control. The guard counts these in a traversal.
func autonomySearchServiceRefusal(result dataplane.NodeCheckResult) bool {
	if nodequality.ServiceFailure(string(result.Verdict), result.TestLevel, result.Stage, result.ErrorCode, result.DirectLeak) {
		return true
	}
	return result.DirectControl == "measured" && nodestore.SearchServiceRefusal(nodestore.SearchServiceOutcome{Available: result.Available, Verdict: string(result.Verdict),
		TestLevel: result.TestLevel, Stage: result.Stage, ErrorCode: result.ErrorCode, EgressIP: result.EgressIP, HTTPStatus: result.HTTPStatus, DirectLeak: result.DirectLeak})
}

// This consumes one search candidate, never grants Apply or assigns a source
// reputation penalty. Local errors and fresh identity/permission checks must
// already have closed through the ordinary check-and-record owner.
func autonomySearchTerminalFailure(result dataplane.NodeCheckResult) bool {
	if autonomySearchServiceRefusal(result) {
		return true
	}
	if result.Available || result.DirectLeak || result.Verdict != evidence.VerdictError || result.HTTPStatus != 0 || result.EgressIP != "" {
		return false
	}
	return result.DirectControl == "measured" && result.TestLevel == "protocol" && result.Stage == "egress" && result.ErrorCode == "node-egress-failed" ||
		result.DirectControl == "not_run" && result.TestLevel == "transport" && result.Stage == "transport" && result.ErrorCode == "node-transport-failed"
}

// A service timeout schedules another pending peer; it is neither a node
// failure nor usable evidence. Only the completed original checker and its
// exact identity may supply this narrowly typed result.
func autonomySearchServiceTimeout(result dataplane.NodeCheckResult, engine, id, service, profile string, started, now time.Time) bool {
	return exactNodeResultIdentity(result, engine, id, service, profile) &&
		result.ProbeID != "" && !result.StartedAt.IsZero() && !result.StartedAt.Before(started) &&
		!result.FinishedAt.Before(result.StartedAt) && !result.FinishedAt.After(now) && result.ExpiresAt.After(now) &&
		!result.Available && !result.DirectLeak && result.Verdict == evidence.VerdictError &&
		result.TestLevel == "service" && result.Stage == "service" && result.ErrorCode == "request-failed" &&
		result.ServiceErrorCategory == "service_timeout" && result.HTTPStatus == 0 && result.EgressIP != "" &&
		result.DirectControl == "measured" && result.CleanupStatus == dataplane.NodeCleanupVerified
}

func autonomyNodeEngine(route string) string {
	if strings.HasPrefix(route, "xray:") || route == "xray" {
		return "xray"
	}
	return "sing-box"
}

// Until the existing ranking owner supplies an engine-aware scorer, never use
// Sing-box history as Xray utility. Keep the healthy exact primary first.
func orderAutonomyExactReserves(ids []string, keep string) []string {
	ordered := slices.Clone(ids)
	slices.Sort(ordered)
	if i := slices.Index(ordered, keep); i > 0 {
		ordered = append([]string{keep}, append(ordered[:i], ordered[i+1:]...)...)
	}
	return ordered
}

func autonomyTraversalVersion(p autonomy.Policy, s autonomy.Service, engine, profile string) string {
	if s.ExpectedRoute == "auto" {
		// Revisit candidates consumed by the old Sing-box-only AUTO traversal.
		engine += ":compatible-v1"
	}
	data, _ := json.Marshal(struct {
		Revision           uint64
		Service            autonomy.Service
		Engine, Network    string
		Sources, Protocols []string
	}{p.Revision, s, engine, profile, p.SourceIDs, p.Protocols})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Use the same scope-bound traversal for checking and passive feed refill.
func (a *App) autonomySearchVersion(p autonomy.Policy, s autonomy.Service, engine, profile string, cfg config.Config) (string, bool) {
	version := autonomyTraversalVersion(p, s, engine, profile)
	if engine != "xray" || cfg.AppliedServices[s.ID].Enabled || !a.autonomyHomeWebCheck(cfg, p, s) &&
		(!a.autonomyUsesHomeXray(cfg, p, s) || !errors.Is(dataplane.XrayHomeForwardingCapability(), dataplane.ErrXrayHomeNativePath)) {
		return version, false
	}
	authority, _ := json.Marshal(struct {
		Version string
		Policy  *config.NetworkPolicy
		Consent *config.DefaultRouteConsent
	}{version, cfg.NetworkPolicy, cfg.DefaultRouteConsent})
	sum := sha256.Sum256(authority)
	return hex.EncodeToString(sum[:]), true
}

// A feed can rotate through more than MaxNodes over the life of a traversal.
// Reclaim room only when a new page needs it. An ineligible or cooling node
// still in the catalog keeps its already-consumed turn.
func makeRoomForAutonomyPage(t *autonomy.Traversal, version string, ids []string, catalogNodes []nodestore.Node) {
	if t == nil || t.Version != version || t.Cursor+len(ids) <= nodestore.MaxNodes {
		return
	}
	newIDs := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		newIDs[id] = struct{}{}
	}
	consumed := t.Ordered[:t.Cursor]
	for _, id := range consumed {
		delete(newIDs, id)
	}
	slotsNeeded := len(consumed) + len(newIDs) - nodestore.MaxNodes
	if slotsNeeded <= 0 {
		return
	}
	present := make(map[string]struct{}, len(catalogNodes))
	for _, n := range catalogNodes {
		present[n.ID] = struct{}{}
	}
	ordered := make([]string, 0, len(t.Ordered))
	for _, id := range consumed {
		if _, ok := present[id]; !ok && slotsNeeded > 0 {
			slotsNeeded--
			continue
		}
		ordered = append(ordered, id)
	}
	cursor := len(ordered)
	t.Ordered = append(ordered, t.Ordered[t.Cursor:]...)
	t.Cursor = cursor
}

// Keep the consumed prefix and pending order across checks/restarts. New feed
// pages append rather than re-ranking old candidates after every observation.
func prepareAutonomyTraversal(r *autonomy.Runtime, version string, ids []string, now time.Time) {
	if r.Search == nil || r.Search.Version != version {
		ordered := slices.Clone(ids)
		r.Search = &autonomy.Traversal{Version: version, Ordered: ordered, Exhausted: len(ordered) == 0}
		return
	}
	t := r.Search
	ordered := slices.Clone(t.Ordered[:t.Cursor])
	for _, id := range t.Ordered[t.Cursor:] {
		if slices.Contains(ids, id) {
			ordered = append(ordered, id)
		}
	}
	for _, id := range ids {
		if !slices.Contains(ordered, id) && len(ordered) < nodestore.MaxNodes {
			ordered = append(ordered, id)
		}
	}
	t.Ordered = ordered
	t.Exhausted = t.Cursor == len(ordered)
	// A new page takes priority over retrying the old prefix, including when
	// its provider cooldown outlasted this local recheck interval.
	if !t.Halted && t.Exhausted && !t.RetryAt.IsZero() && !now.Before(t.RetryAt) {
		r.Search = nil
		prepareAutonomyTraversal(r, version, ids, now)
	}
}

// Priority is a hint, so it cannot promote an inconclusive peer ahead of
// pending peers that have not had their turn. History only schedules: even a
// generic service request error grants no failure, cursor advance or Apply.
func orderAutonomyRecentUnconfirmed(t *autonomy.Traversal, priorityCount int, previous []string, recent map[string]bool) int {
	pending := t.Ordered[t.Cursor:]
	priority := priorityCount
	ready, deferred := []string{}, []string{}
	for i, id := range pending {
		if recent[id] {
			if i < priorityCount {
				priority--
			}
		} else {
			ready = append(ready, id)
		}
	}
	// Keep the durable rotation among already tried peers, even if readiness
	// or source hints would otherwise put the same peer first on every round.
	for _, id := range previous {
		if recent[id] {
			deferred = append(deferred, id)
		}
	}
	t.Ordered = append(append(slices.Clone(t.Ordered[:t.Cursor]), ready...), deferred...)
	return priority
}

func (a *App) prioritizeAutonomyUntriedService(ctx context.Context, p autonomy.Policy, s autonomy.Service, r *autonomy.Runtime, engine, profile string, previous []string, priorityCount int, now time.Time) (int, error) {
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil {
		return 0, err
	}
	recent := map[string]bool{}
	for _, node := range snapshot.Nodes {
		if !slices.Contains(previous, node.ID) {
			continue
		}
		potential := slices.ContainsFunc(node.Health.History, func(record nodestore.CheckRecord) bool {
			return record.ServiceID == s.ID && record.NetworkProfile == profile && record.Verdict == "ERROR" && record.ErrorCode == "request-failed"
		})
		if !potential {
			continue
		}
		candidateEngine, err := a.autonomyCandidateEngine(ctx, p, s, engine, node.ID)
		if err != nil {
			continue // A missing scheduling hint grants nothing.
		}
		var latest nodestore.CheckRecord
		for _, record := range node.Health.History {
			if record.ServiceID == s.ID && record.NetworkProfile == profile && record.RoutePathID == candidateEngine+":"+node.ID && record.CheckedAt.After(latest.CheckedAt) {
				latest = record
			}
		}
		recent[node.ID] = !latest.CheckedAt.IsZero() && !latest.CheckedAt.After(now) && latest.ExpiresAt.After(now) &&
			latest.TestLevel == "service" && (latest.Stage == "service" || latest.Stage == "service_ip") && latest.Verdict == "ERROR" &&
			latest.ErrorCode == "request-failed" && latest.HTTPStatus == 0 && latest.EgressIP != "" && !latest.DirectLeak
	}
	return orderAutonomyRecentUnconfirmed(r.Search, priorityCount, previous, recent), nil
}

// Unlike the legacy status publisher, this save returns I/O errors. Every
// cursor and Apply-budget write is a prerequisite, never a best-effort hint.
func (a *App) persistAutonomySearch(ctx context.Context, revision uint64, id string, r autonomy.Runtime) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := a.autonomy.doc.Services[id]; !ok || a.autonomy.blocked || a.autonomy.doc.Policy.Revision != revision {
		return dataplane.ErrReviewChanged
	}
	previous, existed := a.autonomy.doc.Runtime[id]
	a.autonomy.doc.Runtime[id] = r.Clone()
	if err := a.persistAutonomyLocked(ctx); err != nil {
		if existed {
			a.autonomy.doc.Runtime[id] = previous
		} else {
			delete(a.autonomy.doc.Runtime, id)
		}
		return errors.Join(errAutonomySearchPersistence, err)
	}
	return nil
}

func (a *App) runAutonomyFirstUsable(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, engine, profile, current string, ids []string, catalogNodes []nodestore.Node, personalPriorities map[string]bool) autonomy.Runtime {
	store := a.Store
	finish := func(state, message string) autonomy.Runtime { r.State, r.Message = state, message; return r }
	guard := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		if a.Store != store || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" || !reflect.DeepEqual(a.Store.Get(), cfg) || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(c) != nil {
			return dataplane.ErrReviewChanged
		}
		latest, ok := a.autonomyService(s.ID)
		if !ok || autonomyDefinition(latest) != s.Definition {
			return dataplane.ErrReviewChanged
		}
		if err := a.autonomyResourceGuard(c, p, s, cfg, service); err != nil {
			return err
		}
		observed, err := a.freshNetworkProfile(c)
		if err != nil || observed != profile {
			return dataplane.ErrNetworkChanged
		}
		return nil
	}
	if err := guard(ctx); err != nil {
		return finish("paused", "Подбор отменён: разрешения или сеть изменились.")
	}
	if r.Search != nil && r.Search.Halted {
		return finish("requires-review", "Предыдущая попытка применения требует проверки; дальнейший подбор остановлен.")
	}
	if cfg.AppliedServices[s.ID].Enabled && s.ExpectedRoute == "auto" && len(p.SourceIDs) != 0 {
		// The worker reads personal preferences during initial setup. A new
		// search after a confirmed failure must use the latest library choices.
		now := time.Now()
		snapshot, err := a.Nodes.SnapshotWithPriority(ctx, now)
		if err != nil {
			return finish("catalog-unavailable", "Каталог приоритетных подключений недоступен. Подбор отложен.")
		}
		personalPriorities = autonomyPersonalPriorities(p, snapshot, now)
	}
	traversal := r.Search
	version, homeCheckOnly := a.autonomySearchVersion(p, s, engine, profile, cfg)
	webCheckOnly := autonomyDomainService(service)
	checkedMessage := homeServiceCheckedMessage
	if webCheckOnly {
		h, _ := ctx.Value(autonomyHomeScopeKey{}).(*autonomyXrayHomeRound)
		if !homeCheckOnly || h == nil || !h.webCheckOnly || !h.current(ctx, a, cfg, s) {
			return finish(autonomyStateDomainRouteUnavailable, "Для доменного сервиса недоступна отдельная проверка узла.")
		}
		checkedMessage = service.Probes[0].Label + " ответила через узел Xray. Узел сохранён в резерве. Маршрут для домашних устройств не применён."
	}
	if homeCheckOnly {
		if r.Search == nil || r.Search.Version != version {
			r.Reserves, r.ReserveCheckedAt = nil, time.Time{}
		}
		cached := r
		if hint, ok := ctx.Value(homeReserveHintKey{}).(homeReserveHint); ok && hint.version == version {
			cached.Reserves, cached.ReserveCheckedAt = []string{hint.node}, hint.checkedAt
		}
		if r.Search != nil && r.Search.Version == version && len(cached.Reserves) == 1 && !cached.ReserveCheckedAt.IsZero() {
			now := time.Now()
			if until := a.autonomyHomeReserveUntil(ctx, p, s, cached, ids, catalogNodes, profile, now); until.After(now) {
				if guard(ctx) != nil {
					return finish("paused", "Разрешения или сеть изменились во время чтения результата.")
				}
				if r.NextCheck.IsZero() || r.NextCheck.After(until) {
					r.NextCheck = until
				}
				r.Reserves, r.ReserveCheckedAt = cached.Reserves, cached.ReserveCheckedAt
				r.ReserveValidUntil, r.ReserveConfigRevision = until, cfg.Revision
				return finish(homeServiceCheckedState, checkedMessage)
			}
			r.Reserves, r.ReserveCheckedAt = nil, time.Time{}
			// The only usable reserve may expire before the queue's ordinary
			// exhausted-page retry. Permit the next guarded check at expiry.
			if r.Search.Exhausted && !r.Search.Halted && r.Search.RetryAt.After(now) {
				r.Search.RetryAt = now
			}
		}
	}
	makeRoomForAutonomyPage(r.Search, version, ids, catalogNodes)
	prepareAutonomyTraversal(&r, version, ids, time.Now())
	refusals := a.autonomyServiceRefusals(s.ID, r.Search.Version)
	if r.Search != traversal {
		// A new traversal starts its own run of service refusals.
		refusals = autonomyServiceRefusals{version: r.Search.Version}
		a.setAutonomyServiceRefusals(s.ID, refusals)
	}
	previousPending := slices.Clone(r.Search.Ordered[r.Search.Cursor:])
	now := time.Now()
	var peerNodes map[string]bool
	if homeCheckOnly && webCheckOnly {
		peerNodes = a.homeQueuePeerNodes(ctx, p, s, r, cfg, engine, profile, ids, catalogNodes, now)
	}
	a.prioritizeAutonomyFreshProofs(ctx, p, s, &r, engine, profile, ids, now, peerNodes)
	priorityCount, priorityErr := a.prioritizeAutonomySources(ctx, p, &r, time.Now(), personalPriorities)
	if priorityErr != nil {
		return finish("catalog-unavailable", "Каталог приоритетных источников недоступен; подбор отложен.")
	}
	priorityCount, priorityErr = a.prioritizeAutonomyUntriedService(ctx, p, s, &r, engine, profile, previousPending, priorityCount, time.Now())
	if priorityErr != nil {
		return finish("catalog-unavailable", "Каталог узлов недоступен; подбор отложен.")
	}
	if err := a.persistAutonomySearch(ctx, p.Revision, s.ID, r); err != nil {
		return finish("requires-review", "Не удалось сохранить ход подбора; переключение остановлено.")
	}
	personalFirst := len(personalPriorities) != 0
	hasPriorities := personalFirst || len(p.PreferredSourceIDs) != 0
	standardRoutes := func() (autonomy.Runtime, bool) {
		if webCheckOnly || cfg.AppliedServices[s.ID].Enabled || !hasPriorities || r.Search.StandardRoutesTried {
			return r, false
		}
		// Scheduling metadata only. Persist before the standard phase so later
		// public-node rounds/restarts cannot repeatedly starve behind its probes.
		r.Search.StandardRoutesTried = true
		if err := a.persistAutonomySearch(ctx, p.Revision, s.ID, r); err != nil {
			return finish("requires-review", "Не удалось сохранить ход подбора; переключение остановлено."), true
		}
		routes := p.PreferredRoutes
		if personalFirst {
			routes = slices.DeleteFunc(slices.Clone(routes), func(route string) bool { return route == "nfqws2" })
		}
		next, done := a.tryAutonomyRoutePhase(ctx, p, s, r, cfg, service, profile, routes, 0, a.autonomyNFQWS2DomainOnlyProfile)
		r = next
		return r, done
	}
	if r.Search.Exhausted {
		if r.Search.RetryAt.IsZero() && hasPriorities && len(r.Search.Ordered) > 0 {
			r.Search.RetryAt = time.Now().Add(time.Duration(p.ReserveSeconds) * time.Second)
			if err := a.persistAutonomySearch(ctx, p.Revision, s.ID, r); err != nil {
				return finish("requires-review", "Не удалось сохранить ход подбора; переключение остановлено.")
			}
		}
		if next, done := standardRoutes(); done {
			return next
		}
		if autonomyWaitingForComponent(r) || autonomyWaitingForTunnel(r) {
			return r
		}
		message := "Очередь узлов пройдена. Автопилот ожидает пополнения из разрешённых источников или повторной проверки."
		if len(p.SourceIDs) == 0 {
			message = "Источники узлов не разрешены в настройках автопилота. Проверки узлов не запускались."
		} else if len(r.Search.Ordered) == 0 {
			message = "В разрешённых источниках сейчас нет подходящих узлов для проверки этого сервиса."
		}
		if prerequisite := a.autonomyMissingTunnelPrerequisite(p, cfg, service); prerequisite != "" {
			message += " " + prerequisite
		}
		return finish("searching", message)
	}
	if time.Now().Before(refusals.until) {
		return finish("service-unconfirmed", autonomyServiceUnconfirmedMessage)
	}
	// The library cursor is a ring. Present only the remaining suffix, so its
	// per-call examined bound cannot wrap into an already consumed prefix when
	// the last round has fewer entries than the checker budget.
	offset := r.Search.Cursor
	startedCursor := offset
	remaining := r.Search.Ordered[offset:]
	checkState, checkMessage := "", ""
	componentState, componentMessage := "", ""
	var componentRetry time.Time
	checkedNode := ""
	var usableCheck nodestore.SearchCheck
	var usableUntil time.Time
	// The check the next cursor write consumes, if any; a skipped candidate
	// is not an observation and leaves the run of refusals unchanged.
	observed, refused := false, false
	hooks := nodestore.SearchHooks{
		Guard: func(c context.Context) error {
			if err := guard(c); err != nil {
				return err
			}
			// Stop right after the cursor write that consumed the last
			// refusal the guard allows, before any further check.
			if time.Now().Before(refusals.until) {
				return errAutonomyServiceRefusals
			}
			return nil
		},
		Check: func(c context.Context, id string) (nodestore.SearchCheck, error) {
			candidateEngine, err := a.autonomyCandidateRequirement(c, p, s, engine, id)
			if err == dataplane.ErrExactNodeUnsupported {
				return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
			}
			if err != nil {
				return nodestore.SearchCheck{}, err
			}
			if candidateEngine != engine {
				if a.autonomyCapabilityRefusal(cfg, s.ID, candidateEngine+":node-") != nil {
					return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
				}
				if _, err := a.nodeCheckerForEngine(candidateEngine); err != nil {
					componentState, componentMessage = "component-unavailable", "Для совместимого движка недоступна точная проверка подключений."
					return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
				}
				if componentState == "" {
					name := "Sing-box"
					if candidateEngine == "xray" {
						name = "Xray"
					}
					componentState, componentMessage, componentRetry = a.prepareAutonomyComponent(c, p, s, cfg, service, candidateEngine, name, func(ctx context.Context) bool { return guard(ctx) == nil })
				}
				if componentState == "paused" || componentState == "requires-review" {
					checkState, checkMessage = componentState, componentMessage
					return nodestore.SearchCheck{}, nodestore.ErrSearchInconclusive
				}
				if componentState != "" {
					return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
				}
			}
			checkStarted := time.Now()
			check, err := a.checkAutonomyReserveForEngine(c, p, s, cfg, candidateEngine, id, service, profile)
			// These exact refusals with no result precede transport and cleanup.
			// An approved compatible executor can try the same candidate once.
			// Any actual first observation stays with its executor.
			if (err == dataplane.ErrExactNodeUnsupported || err == dataplane.ErrExactNodeRuntime) && reflect.DeepEqual(check, dataplane.NodeCheckResult{}) {
				if guardErr := guard(c); guardErr != nil {
					return nodestore.SearchCheck{}, guardErr
				}
				if alternate := a.autonomyAlternateCandidateEngine(c, cfg, p, s, candidateEngine, id); alternate != "" {
					now := time.Now()
					nodes, snapshotErr := a.Nodes.Snapshot(c, now)
					if snapshotErr != nil {
						return nodestore.SearchCheck{}, snapshotErr
					}
					if !slices.ContainsFunc(nodes.Nodes, func(n nodestore.Node) bool {
						return n.ID == id && allowedAutonomyNode(p, n, time.Now())
					}) {
						return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
					}
					candidateEngine, checkStarted = alternate, time.Now()
					check, err = a.checkAutonomyReserveForEngine(c, p, s, cfg, candidateEngine, id, service, profile)
				}
			}
			if err == dataplane.ErrExactNodeUnsupported && c.Err() == nil && check.ErrorCode != "node-cleanup-failed" {
				return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
			}
			if err == nil && (autonomyRouteObservation{RetryAfterSeconds: nodeServiceRateLimitSeconds(check, time.Now())}).pause(&r) {
				checkState, checkMessage = r.State, r.Message
				return nodestore.SearchCheck{}, nodestore.ErrSearchInconclusive
			}
			if err == nil && autonomySearchServiceTimeout(check, candidateEngine, id, service.ID, profile, checkStarted, time.Now()) &&
				len(r.Search.Ordered)-r.Search.Cursor > 1 && r.Search.Ordered[r.Search.Cursor] == id {
				if err := guard(c); err != nil {
					return nodestore.SearchCheck{}, err
				}
				pending := r.Search.Ordered[r.Search.Cursor:]
				r.Search.Ordered = append(append(slices.Clone(r.Search.Ordered[:r.Search.Cursor]), pending[1:]...), id)
				r.State, r.Message = "searching", "Сервис не ответил вовремя. Подбор продолжится с другого ожидающего узла; этот узел будет проверен позже."
				if err := a.persistAutonomySearch(c, p.Revision, s.ID, r); err != nil {
					return nodestore.SearchCheck{}, err
				}
				checkState, checkMessage = r.State, r.Message
				return nodestore.SearchCheck{}, nodestore.ErrSearchInconclusive
			}
			if state, message := autonomyReserveCheckStop(c, check, err); state != "" {
				checkState, checkMessage = state, message
				if err == nil {
					err = nodestore.ErrSearchInconclusive
				}
				return nodestore.SearchCheck{}, err
			}
			outcome := nodestore.SearchDefiniteFailure
			if autonomyNodeObservation(check, time.Now()) == "PASS" {
				outcome = nodestore.SearchUsable
			} else {
				if !autonomySearchTerminalFailure(check) {
					checkState, checkMessage = "unconfirmed", "Проверка не подтвердила отказ сервиса; узел не признан неисправным."
					return nodestore.SearchCheck{}, nodestore.ErrSearchInconclusive
				}
				// Besides the cursor, consuming a failure also drops the node from
				// this service's reserves; a later fresh PASS can list it again.
				// It records no candidate failure, cleanup or source penalty.
				r.Reserves = slices.DeleteFunc(r.Reserves, func(candidate string) bool { return candidate == id })
			}
			observed, refused = true, outcome == nodestore.SearchDefiniteFailure && autonomySearchServiceRefusal(check)
			record := nodestore.SearchCheck{Outcome: outcome, ProbeID: check.ProbeID, CheckedAt: check.FinishedAt, Engine: candidateEngine}
			if outcome == nodestore.SearchUsable {
				checkedNode, usableCheck = id, record
				usableUntil = minTime(check.ExpiresAt, record.CheckedAt.Add(time.Duration(p.ReserveSeconds)*time.Second))
			}
			return record, nil
		},
		PersistCursor: func(c context.Context, next int) error {
			if next == 0 {
				next = len(remaining)
			}
			r.Search.Cursor = offset + next
			r.Search.Exhausted = r.Search.Cursor == len(r.Search.Ordered)
			if r.Search.Exhausted {
				r.Search.RetryAt = time.Now().Add(time.Duration(p.ReserveSeconds) * time.Second)
			}
			counted := refusals
			if observed {
				counted = counted.observe(refused)
			}
			observed, refused = false, false
			if counted.count >= autonomyServiceRefusalLimit {
				// Pause instead of consuming the rest of the list. After RetryAt
				// the search resumes at the cursor with a new run.
				if !r.Search.Exhausted {
					r.Search.RetryAt = time.Now().Add(time.Duration(p.ReserveSeconds) * time.Second)
				}
				counted = autonomyServiceRefusals{version: counted.version, until: r.Search.RetryAt}
			}
			if err := a.persistAutonomySearch(c, p.Revision, s.ID, r); err != nil {
				return err
			}
			refusals = counted
			a.setAutonomyServiceRefusals(s.ID, refusals)
			return nil
		},
		Apply: func(c context.Context, route nodestore.ResolvedRoute) error {
			r.Reserves = slices.DeleteFunc(r.Reserves, func(id string) bool { return id == current })
			if !slices.Contains(r.Reserves, route.NodeID) && len(r.Reserves) < p.ReserveTarget {
				r.Reserves = append(r.Reserves, route.NodeID)
			}
			if len(r.CandidateFailures) >= 4 || !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
				return errAutonomySearchBudget
			}
			r.State, r.Message = "applying", "Первый подходящий узел проверен; выполняется транзакция."
			// A crash or untrusted failure must not turn a consumed cursor into
			// permission to attempt the next peer on a later round/restart.
			r.Search.Halted = true
			if err := a.persistAutonomySearch(c, p.Revision, s.ID, r); err != nil {
				return err
			}
			return a.applyAutonomyRoute(c, p, s, cfg, profile, route.Route)
		},
		ContinueAfterRollback: func(c context.Context, route nodestore.ResolvedRoute, applyErr error) (bool, error) {
			if h, ok := c.Value(autonomyHomeScopeKey{}).(*autonomyXrayHomeRound); ok && !h.afterRollback(c, cfg, applyErr) {
				return false, nil
			}
			failure, ok := a.autonomyCandidateRollbackForEngine(c, p, s, cfg, autonomyNodeEngine(route.Route), profile, route.NodeID, applyErr)
			canaryTimeout := false
			if !ok && a.autonomyCandidateCanaryTimeout(c, p, s, cfg, profile, route.NodeID, applyErr) {
				ok = true // No negative node/source observation is recorded.
				canaryTimeout = true
			}
			if !ok {
				return false, nil
			}
			if failure.NodeID != "" {
				r.RecordCandidateFailure(failure)
			}
			r.Reserves = slices.DeleteFunc(r.Reserves, func(id string) bool { return id == route.NodeID })
			if canaryTimeout {
				return a.resumeAutonomyAfterCanary(c, p.Revision, s.ID, &r, guard)
			}
			r.Search.Halted = false
			if err := a.persistAutonomySearch(c, p.Revision, s.ID, r); err != nil {
				return false, err
			}
			return true, guard(c)
		},
	}
	checksLeft := p.CandidatesPerRound
	search := func(count int) (nodestore.SearchResult, error) {
		offset = r.Search.Cursor
		remaining = r.Search.Ordered[offset : offset+count]
		result, err := a.Nodes.SearchFirstUsable(ctx, nodestore.SearchRequest{
			Engine: engine, ServiceID: s.ID, NetworkProfile: profile, Ordered: remaining,
			Current: current, Cursor: 0, Limit: checksLeft,
			AllowedSources: p.SourceIDs, Protocols: p.Protocols, CheckOnly: homeCheckOnly,
		}, hooks)
		checksLeft -= result.Checks
		return result, err
	}
	var result nodestore.SearchResult
	var err error
	priorityEnd := offset + priorityCount
	if priorityCount > 0 {
		result, err = search(priorityCount)
	}
	if err == nil && result.Applied.NodeID == "" && result.Verified.NodeID == "" && r.Search.Cursor >= priorityEnd {
		if next, done := standardRoutes(); done {
			return next
		}
		if checksLeft > 0 && !r.Search.Exhausted {
			result, err = search(len(r.Search.Ordered) - r.Search.Cursor)
		}
	}
	if result.Applied.NodeID != "" {
		// Search verifies this SAME durable exact PASS before Apply and only
		// publishes Applied after a successful transaction. Keep its actual
		// check time, never a UI/commit clock or a rejected peer's observation.
		if result.Applied.NodeID == checkedNode && result.Applied.Route == usableCheck.Engine+":"+checkedNode {
			r.CheckedAt = usableCheck.CheckedAt
		}
		r.Search.Halted = false
		r.Reserves = []string{result.Applied.NodeID}
		r.Failures = 0
		r.FirstFailure, r.LastFailure = time.Time{}, time.Time{}
		return finish("applied", "Первый подходящий узел применён к этому сервису и его устройствам.")
	}
	if err == nil && result.Verified.NodeID != "" && homeCheckOnly && usableCheck.Engine == "xray" && checkedNode == result.Verified.NodeID && result.Verified.Route == "xray:"+checkedNode {
		now := time.Now()
		var sourceUntil time.Time
		for _, node := range catalogNodes {
			if node.ID == checkedNode {
				sourceUntil = allowedAutonomyNodeUntil(p, node, now)
				break
			}
		}
		usableUntil = minTime(usableUntil, sourceUntil)
		if !now.Before(usableUntil) {
			return finish("pending", "Срок подтверждения узла истёк. Ожидается повторная проверка.")
		}
		r.Reserves = []string{checkedNode}
		r.ReserveCheckedAt = usableCheck.CheckedAt
		r.ReserveValidUntil, r.ReserveConfigRevision = usableUntil, cfg.Revision
		if r.NextCheck.IsZero() || r.NextCheck.After(usableUntil) {
			r.NextCheck = usableUntil
		}
		return finish(homeServiceCheckedState, checkedMessage)
	}
	if errors.Is(err, errAutonomySearchPersistence) {
		return finish("requires-review", "Не удалось сохранить ход подбора; переключение остановлено.")
	}
	if errors.Is(err, errAutonomySearchBudget) {
		return finish("rate-limited", "Лимит переключений исчерпан; применение отложено.")
	}
	if errors.Is(err, errAutonomyServiceRefusals) {
		return finish("service-unconfirmed", autonomyServiceUnconfirmedMessage)
	}
	if err != nil {
		if checkState != "" {
			return finish(checkState, checkMessage)
		}
		if state, message, blocked := autonomyRouteDependency(err, &r); blocked {
			return finish(state, message)
		}
		state, message := autonomyApplyFailureStatus(err)
		return finish(state, message)
	}
	if r.Search.Exhausted && componentState != "" {
		if componentRetry.After(time.Now()) {
			r.Search.RetryAt = minTime(r.Search.RetryAt, componentRetry)
			r.NextCheck = minTime(r.NextCheck, componentRetry)
			componentMessage = autonomyComponentRetryMessage(componentMessage, componentRetry, p.Timezone)
		}
		return finish(componentState, componentMessage)
	}
	r.State, r.Message = "searching", "Подходящий узел пока не найден; ограниченный подбор продолжится."
	// Continuing a finite cold traversal is not a health recheck. Yield the
	// admission and resume on a later coordinator tick after durable progress.
	// Errors (including timeout rotation without consumption) returned above;
	// RetryAt, exhausted/halted searches and applied-route recovery keep their
	// existing pacing. Every continuation still enters the same guards/Apply.
	finished := time.Now()
	if ctx.Err() == nil && !cfg.AppliedServices[s.ID].Enabled && r.Search.Cursor > startedCursor && firstAutonomySearchDue(r, finished) {
		r.NextCheck = finished.Add(reconcilerPollInterval)
	}
	return r
}

// A reserve of another service can move an untried public peer forward. The
// target service's own check and all original publication gates still run.
func (a *App) homeQueuePeerNodes(ctx context.Context, p autonomy.Policy, target autonomy.Service, r autonomy.Runtime, cfg config.Config, engine, profile string, eligible []string, nodes []nodestore.Node, now time.Time) map[string]bool {
	hints, _ := ctx.Value(homeQueueHintsKey{}).([]homeQueueHint)
	var preferred map[string]bool
	for _, hint := range hints {
		if !hint.validUntil.After(now) || !slices.Contains(eligible, hint.node) || r.CandidateCoolingDown(hint.node) || !slices.Contains(r.Search.Ordered[r.Search.Cursor:], hint.node) {
			continue
		}
		version, home := a.autonomySearchVersion(p, hint.service, engine, profile, cfg)
		if !home || hint.version != version {
			continue
		}
		index := slices.IndexFunc(nodes, func(n nodestore.Node) bool { return n.ID == hint.node })
		if index < 0 {
			continue
		}
		node := nodes[index]
		if !strings.EqualFold(node.Protocol, "vless") || !slices.ContainsFunc(node.Origins, func(o nodestore.Origin) bool {
			return providerfeed.SourceOrder(o.SourceID) > 0 && allowedAutonomyOrigin(p, o, now)
		}) || slices.ContainsFunc(node.Health.History, func(rec nodestore.CheckRecord) bool {
			return rec.ServiceID == target.ID && rec.NetworkProfile == profile && rec.RoutePathID == engine+":"+node.ID && rec.ExpiresAt.After(now)
		}) {
			continue
		}
		candidateEngine, err := a.autonomyCandidateEngine(ctx, p, target, engine, node.ID)
		if err != nil || candidateEngine != "xray" {
			continue
		}
		peer := autonomy.Runtime{Reserves: []string{node.ID}, ReserveCheckedAt: hint.checkedAt}
		if !a.autonomyHomeReserveUntil(ctx, p, hint.service, peer, eligible, nodes, profile, now).After(now) {
			continue
		}
		if preferred == nil {
			preferred = make(map[string]bool)
		}
		preferred[node.ID] = true
	}
	return preferred
}

// Proof is only a scheduling hint. SearchFirstUsable still checks the exact
// candidate afresh and persists its receipt before the ordinary Apply gate.
// Never replay a consumed candidate or clear an untrusted application latch.
func (a *App) prioritizeAutonomyFreshProofs(ctx context.Context, p autonomy.Policy, s autonomy.Service, r *autonomy.Runtime, engine, profile string, eligible []string, now time.Time, peerNodes map[string]bool) {
	if r.Search == nil || r.Search.Halted || a.Nodes == nil {
		return
	}
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil {
		return
	}
	nodes := map[string]nodestore.Node{}
	for _, n := range snapshot.Nodes {
		nodes[n.ID] = n
	}
	t := r.Search
	preferred, peers, rest := []string{}, []string{}, []string{}
	for _, id := range t.Ordered[t.Cursor:] {
		fresh := false
		// Avoid reopening the private catalogue for every unchecked/failed
		// row. This display-history prefilter grants no authority: resolution
		// and the runtime-contract check below remain mandatory.
		potential := slices.ContainsFunc(nodes[id].Health.History, func(check nodestore.CheckRecord) bool {
			return check.ServiceID == s.ID && check.NetworkProfile == profile && check.Verdict == "PASS" && check.TestLevel == "service" && now.Before(check.ExpiresAt)
		})
		if potential && slices.Contains(eligible, id) && !r.CandidateCoolingDown(id) && allowedAutonomyNode(p, nodes[id], now) {
			candidateEngine, err := a.autonomyCandidateEngine(ctx, p, s, engine, id)
			if err == nil {
				_, err = a.Nodes.ResolveRouteForEngine(ctx, candidateEngine, id, s.ID, profile, "", time.Time{}, now)
				fresh = err == nil
				if fresh && candidateEngine == "sing-box" {
					// ResolveRoute does not inspect executor defaults. Match the same runtime
					// contract enforced by materialization without changing canonical material.
					fresh = a.Nodes.WithSecret(ctx, id, func(raw []byte) error {
						var outbound map[string]any
						if json.Unmarshal(raw, &outbound) != nil {
							return nodestore.ErrRouteProof
						}
						_, contract := providerprofile.SingBoxRuntimeOutbound(outbound)
						if contract == "" {
							return nil
						}
						for _, check := range nodes[id].Health.History {
							if check.ServiceID == s.ID && check.NetworkProfile == profile && check.RoutePathID == candidateEngine+":"+id {
								if check.RuntimeContract == contract {
									return nil
								}
								return nodestore.ErrRouteProof
							}
						}
						return nodestore.ErrRouteProof
					}) == nil
				}
			}
		}
		if fresh {
			preferred = append(preferred, id)
		} else if peerNodes[id] {
			peers = append(peers, id)
		} else {
			rest = append(rest, id)
		}
	}
	// Among the others, a fresh general connectivity PASS of the readiness
	// pool goes first and repeated failures go last. Nothing is removed.
	rest = a.nodeReadinessOrder(rest, engine, profile, s.ExpectedRoute == "auto", now)
	ordered := slices.Clone(t.Ordered[:t.Cursor])
	ordered = append(ordered, preferred...)
	ordered = append(ordered, peers...)
	t.Ordered = append(ordered, rest...)
}
