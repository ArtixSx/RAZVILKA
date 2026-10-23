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
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

var errAutonomySearchBudget = errors.New("autonomy apply budget exhausted")
var errAutonomySearchPersistence = errors.New("autonomy traversal could not be persisted")

// This consumes one search candidate, never grants Apply or assigns a source
// reputation penalty. Local errors and fresh identity/permission checks must
// already have closed through the ordinary check-and-record owner.
func autonomySearchTerminalFailure(result dataplane.NodeCheckResult) bool {
	if nodequality.ServiceFailure(string(result.Verdict), result.TestLevel, result.Stage, result.ErrorCode, result.DirectLeak) {
		return true
	}
	if result.Available || result.DirectLeak || result.Verdict != evidence.VerdictError || result.HTTPStatus != 0 || result.EgressIP != "" {
		return false
	}
	return result.DirectControl == "measured" && result.TestLevel == "protocol" && result.Stage == "egress" && result.ErrorCode == "node-egress-failed" ||
		result.DirectControl == "not_run" && result.TestLevel == "transport" && result.Stage == "transport" && result.ErrorCode == "node-transport-failed"
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
	added := slices.Clone(ids)
	slices.Sort(added)
	for _, id := range added {
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

// Unlike the legacy status publisher, this save returns I/O errors. Every
// cursor and Apply-budget write is a prerequisite, never a best-effort hint.
func (a *App) persistAutonomySearch(ctx context.Context, id string, r autonomy.Runtime) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if _, ok := a.autonomy.doc.Services[id]; !ok {
		return dataplane.ErrReviewChanged
	}
	a.autonomy.doc.Runtime[id] = r.Clone()
	if err := a.persistAutonomyLocked(ctx); err != nil {
		return errors.Join(errAutonomySearchPersistence, err)
	}
	return nil
}

func (a *App) runAutonomyFirstUsable(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, engine, profile, current string, ids []string) autonomy.Runtime {
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
	prepareAutonomyTraversal(&r, autonomyTraversalVersion(p, s, engine, profile), ids, time.Now())
	a.prioritizeAutonomyFreshProofs(ctx, p, s, &r, engine, profile, ids, time.Now())
	if err := a.persistAutonomySearch(ctx, s.ID, r); err != nil {
		return finish("requires-review", "Не удалось сохранить ход подбора; переключение остановлено.")
	}
	if r.Search.Exhausted {
		return finish("searching", "Доступный снимок проверен. Ожидаем разрешённое пополнение или повторную проверку.")
	}
	// The library cursor is a ring. Present only the remaining suffix, so its
	// per-call examined bound cannot wrap into an already consumed prefix when
	// the last round has fewer entries than the checker budget.
	offset := r.Search.Cursor
	remaining := r.Search.Ordered[offset:]
	checkState, checkMessage := "", ""
	checkedNode := ""
	var usableCheck nodestore.SearchCheck
	result, err := a.Nodes.SearchFirstUsable(ctx, nodestore.SearchRequest{
		Engine: engine, ServiceID: s.ID, NetworkProfile: profile, Ordered: remaining,
		Current: current, Cursor: 0, Limit: p.CandidatesPerRound,
		AllowedSources: p.SourceIDs, Protocols: p.Protocols,
	}, nodestore.SearchHooks{
		Guard: guard,
		Check: func(c context.Context, id string) (nodestore.SearchCheck, error) {
			candidateEngine, err := a.autonomyCandidateEngine(c, p, s, engine, id)
			if err == dataplane.ErrExactNodeUnsupported {
				return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
			}
			if err != nil {
				return nodestore.SearchCheck{}, err
			}
			check, err := a.checkAutonomyReserveForEngine(c, p, s, cfg, candidateEngine, id, service, profile)
			if err == dataplane.ErrExactNodeUnsupported && c.Err() == nil && check.ErrorCode != "node-cleanup-failed" {
				return nodestore.SearchCheck{Outcome: nodestore.SearchUnsupported}, nil
			}
			if err == nil && (autonomyRouteObservation{RetryAfterSeconds: nodeServiceRateLimitSeconds(check, time.Now())}).pause(&r) {
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
				r.Reserves = slices.DeleteFunc(r.Reserves, func(candidate string) bool { return candidate == id })
			}
			record := nodestore.SearchCheck{Outcome: outcome, ProbeID: check.ProbeID, CheckedAt: check.FinishedAt, Engine: candidateEngine}
			if outcome == nodestore.SearchUsable {
				checkedNode, usableCheck = id, record
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
			return a.persistAutonomySearch(c, s.ID, r)
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
			if err := a.persistAutonomySearch(c, s.ID, r); err != nil {
				return err
			}
			return a.applyAutonomyRoute(c, p, s, cfg, profile, route.Route)
		},
		ContinueAfterRollback: func(c context.Context, route nodestore.ResolvedRoute, applyErr error) (bool, error) {
			failure, ok := a.autonomyCandidateRollbackForEngine(c, p, s, cfg, autonomyNodeEngine(route.Route), profile, route.NodeID, applyErr)
			if !ok {
				return false, nil
			}
			if failure.NodeID != "" {
				r.RecordCandidateFailure(failure)
			}
			r.Search.Halted = false
			r.Reserves = slices.DeleteFunc(r.Reserves, func(id string) bool { return id == route.NodeID })
			if err := a.persistAutonomySearch(c, s.ID, r); err != nil {
				return false, err
			}
			return true, guard(c)
		},
	})
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
	if errors.Is(err, errAutonomySearchPersistence) {
		return finish("requires-review", "Не удалось сохранить ход подбора; переключение остановлено.")
	}
	if errors.Is(err, errAutonomySearchBudget) {
		return finish("rate-limited", "Лимит переключений исчерпан; применение отложено.")
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
	return finish("searching", "Подходящий узел пока не найден; ограниченный подбор продолжится.")
}

// Proof is only a scheduling hint. SearchFirstUsable still checks the exact
// candidate afresh and persists its receipt before the ordinary Apply gate.
// Never replay a consumed candidate or clear an untrusted application latch.
func (a *App) prioritizeAutonomyFreshProofs(ctx context.Context, p autonomy.Policy, s autonomy.Service, r *autonomy.Runtime, engine, profile string, eligible []string, now time.Time) {
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
	preferred, rest := []string{}, []string{}
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
		} else {
			rest = append(rest, id)
		}
	}
	ordered := slices.Clone(t.Ordered[:t.Cursor])
	t.Ordered = append(append(ordered, preferred...), rest...)
}
