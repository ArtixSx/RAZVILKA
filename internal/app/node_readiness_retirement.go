package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodecleanup"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// policy is the saved, enabled built-in VLESS selection returned by
// nodeReadinessSourcePolicy(..., true). Even an expired additional origin
// or a user alias keeps the node in the catalogue.
func exclusivelyFreeVLESS(n nodestore.Node, policy autonomy.Policy, now time.Time) bool {
	return !n.HasAlias && !n.Disabled && strings.EqualFold(n.Protocol, "vless") &&
		allowedAutonomyNode(policy, n, now) && len(n.Origins) != 0 && !slices.ContainsFunc(n.Origins, func(o nodestore.Origin) bool {
		return !slices.Contains(policy.SourceIDs, o.SourceID)
	})
}

type freeNodeRetirement struct {
	network  string
	revision uint64
	until    time.Time
}

func (r freeNodeRetirement) active(network string, revision uint64, now time.Time) bool {
	return r.network == network && r.revision == revision && now.Before(r.until)
}

func (a *App) retiredFreeIDs(p autonomy.Policy, snapshot nodestore.Snapshot, network string, now time.Time) map[string]bool {
	a.nodeReadiness.mu.Lock()
	receipts := maps.Clone(a.nodeReadiness.retired)
	a.nodeReadiness.mu.Unlock()
	if len(receipts) == 0 {
		return nil
	}
	allowed := a.nodeReadinessSourcePolicy(p, snapshot, true)
	held := map[string]bool{}
	for _, n := range snapshot.Nodes {
		if receipts[n.ID].active(network, p.Revision, now) && exclusivelyFreeVLESS(n, allowed, now) {
			held[n.ID] = true
		}
	}
	return held
}

// Earlier observations are bounded historical strikes, never current
// connectivity evidence. The most recent strike and the independent peer
// must both still be within the checker's own TTL at the point of removal.
const freeFailureSeriesWindow = 20 * time.Minute

func freeFailureSeriesSpan(count int) time.Duration {
	window := freeFailureSeriesWindow
	// Later rotation strikes are deliberately spaced by the existing backoff.
	for prior := 2; prior < count; prior++ {
		window += nodeReadinessDelay(nodeReadinessEntry{Failures: prior}) + nodeReadinessJitter
	}
	return window
}

type freeConnectivityProof struct {
	probe, engine, network string
	checked, expires       time.Time
	revision               uint64
	outcome                nodeReadinessOutcome
}

func (proof freeConnectivityProof) matchesLatest(item nodeCheckItem) bool {
	return proof.probe != "" && proof.probe == item.ProbeID && proof.engine == item.Engine &&
		proof.network == item.NetworkProfile && proof.checked.Equal(item.CheckedAt) &&
		proof.expires.Equal(item.ExpiresAt) && proof.outcome == nodeReadinessOutcomeOf(item)
}

func (e *nodeReadinessEntry) recordFreeProof(item nodeCheckItem, revision uint64, owned bool, now time.Time) {
	o := nodeReadinessOutcomeOf(item)
	if o == nodeReadinessNotRun || item.ErrorCode == "node-check-canceled" {
		return
	}
	proof := freeConnectivityProof{}
	if owned && (o == nodeReadinessEgress || o == nodeReadinessPass) && item.TestLevel == "connectivity" &&
		item.ProbeID != "" && item.Engine != "" && item.NetworkProfile != "" && !item.CheckedAt.After(now) &&
		item.ExpiresAt.After(now) && item.ExpiresAt.Sub(item.CheckedAt) <= dataplane.NodeConnectivityTTL {
		proof = freeConnectivityProof{item.ProbeID, item.Engine, item.NetworkProfile, item.CheckedAt, item.ExpiresAt, revision, o}
	}
	copy(e.proofs[:], e.proofs[1:])
	e.proofs[len(e.proofs)-1] = proof
}

// Both on receipt and at commit every current origin must have belonged to
// the owner-selected built-in pool since the earliest evidence used.
func freeOriginDeadline(n nodestore.Node, p autonomy.Policy, earliest, now time.Time) time.Time {
	if !exclusivelyFreeVLESS(n, p, now) {
		return time.Time{}
	}
	var until time.Time
	for _, origin := range n.Origins {
		if !allowedAutonomyOrigin(p, origin, earliest) || !allowedAutonomyOrigin(p, origin, now) {
			return time.Time{}
		}
		if until.IsZero() || origin.ExpiresAt.Before(until) {
			until = origin.ExpiresAt
		}
	}
	return until
}

// Keep evidence of other executors, networks and previous successes even
// when ordinary rotation switches WAN and rebuilds its scheduling entries.
type freeConnectivityScope struct {
	network, engine string
	otherScope      bool
	passUntil       time.Time
}

func (c *nodeCheckState) rememberFreeConnectivityScope(item nodeCheckItem) {
	if item.ProbeID == "" || item.Engine == "" || item.NetworkProfile == "" {
		return
	}
	if c.connectivityScopes == nil {
		c.connectivityScopes = map[string]freeConnectivityScope{}
	}
	seen, ok := c.connectivityScopes[item.NodeID]
	if !ok {
		if len(c.connectivityScopes) >= nodestore.MaxNodes {
			c.connectivityScopesSaturated = true
			return
		}
		seen.network, seen.engine = item.NetworkProfile, item.Engine
	}
	seen.otherScope = seen.otherScope || item.NetworkProfile != seen.network || item.Engine != seen.engine
	if nodeReadinessOutcomeOf(item) == nodeReadinessPass && item.ExpiresAt.After(seen.passUntil) {
		seen.passUntil = item.ExpiresAt
	}
	c.connectivityScopes[item.NodeID] = seen
}

type freeRotationObservations struct {
	saturated bool
	service   map[string]freeServiceObservation
	entries   map[string]nodeReadinessEntry
	latest    map[string]nodeCheckItem
	scopes    map[string]freeConnectivityScope
}

func (a *App) freeRotationSnapshot(snap nodestore.Snapshot) freeRotationObservations {
	present := map[string]bool{}
	for _, n := range snap.Nodes {
		present[n.ID] = true
	}

	a.nodeReadiness.mu.Lock()
	for id := range a.nodeReadiness.service {
		if !present[id] {
			delete(a.nodeReadiness.service, id)
		}
	}
	out := freeRotationObservations{service: maps.Clone(a.nodeReadiness.service), entries: maps.Clone(a.nodeReadiness.entries)}
	a.nodeReadiness.mu.Unlock()
	a.nodeChecks.mu.Lock()
	for id := range a.nodeChecks.connectivityScopes {
		if !present[id] {
			delete(a.nodeChecks.connectivityScopes, id)
		}
	}
	out.saturated = a.nodeChecks.connectivityScopesSaturated
	out.latest = maps.Clone(a.nodeChecks.connectivity)
	out.scopes = maps.Clone(a.nodeChecks.connectivityScopes)
	a.nodeChecks.mu.Unlock()
	return out
}

func (rotation freeRotationObservations) deadline(n nodestore.Node, snap nodestore.Snapshot, p autonomy.Policy, network string, engines map[string]bool, now time.Time) time.Time {
	entry := rotation.entries[n.ID]
	count := p.EffectivePublicNodeFailureThreshold()
	if count < 2 || count > len(entry.proofs) {
		return time.Time{}
	}
	strikes := entry.proofs[len(entry.proofs)-count:]
	first, last := strikes[0], strikes[len(strikes)-1]
	seriesUntil := first.checked.Add(freeFailureSeriesSpan(count))
	// Retained service observations or a competing successful connectivity check
	// keep the material. Its scheduling backoff can still change.
	scope, ok := rotation.scopes[n.ID]
	if !ok || scope.otherScope || scope.passUntil.After(first.checked) || scope.network != network || scope.engine != last.engine || len(n.Health.History) > 0 ||
		!engines[last.engine] || !seriesUntil.After(now) ||
		!last.expires.After(now) || last.checked.After(now) || !last.matchesLatest(rotation.latest[n.ID]) {
		return time.Time{}
	}
	probes := make(map[string]bool, count)
	for i, strike := range strikes {
		if strike.probe == "" || probes[strike.probe] || strike.outcome != nodeReadinessEgress ||
			strike.engine != last.engine || strike.network != network || strike.revision != p.Revision ||
			(i > 0 && strike.checked.Sub(strikes[i-1].checked) < nodeReadinessNodeSpacing) {
			return time.Time{}
		}
		probes[strike.probe] = true
	}
	originUntil := freeOriginDeadline(n, p, first.checked, now)
	if originUntil.IsZero() {
		return time.Time{}
	}
	for _, peer := range snap.Nodes {
		peerHistory := rotation.entries[peer.ID].proofs
		pass := peerHistory[len(peerHistory)-1]
		if peer.ID == n.ID || pass.outcome != nodeReadinessPass || pass.engine != last.engine || pass.network != network ||
			pass.revision != p.Revision || !pass.checked.After(first.checked) || pass.checked.After(now) || !pass.expires.After(now) ||
			pass.probe == "" || probes[pass.probe] || !pass.matchesLatest(rotation.latest[peer.ID]) {
			continue
		}
		peerUntil := freeOriginDeadline(peer, p, pass.checked, now)
		if !peerUntil.IsZero() {
			return minTime(minTime(originUntil, peerUntil), minTime(seriesUntil, minTime(last.expires, pass.expires)))
		}
	}
	return time.Time{}
}

// CheckRecord predates policy/scope binding. Only original checks made
// under the autopilot's live review can qualify an automatic failover.
type freeServiceConsent struct {
	revision                   uint64
	service, definition, scope string
	allLAN                     bool
	resources                  [32]byte
}

func freeServiceBinding(p autonomy.Policy, s autonomy.Service, cfg config.Config) freeServiceConsent {
	resources, _ := json.Marshal([]any{cfg.NetworkPolicy, cfg.InactiveResourceExclusions})
	return freeServiceConsent{p.Revision, s.ID, s.Definition, autonomy.ScopeFingerprint(s.Sources), s.AllLAN, sha256.Sum256(resources)}
}

type freeServiceObservation struct {
	consent         freeServiceConsent
	probes          [autonomy.MaxPublicNodeFailureThreshold]string
	appliedFailures [autonomy.MaxPublicNodeFailureThreshold]uint64
}

func (o freeServiceObservation) confirmedAppliedRevision(count int) uint64 {
	if count < 2 || count > len(o.appliedFailures) {
		return 0
	}
	revisions := o.appliedFailures[len(o.appliedFailures)-count:]
	revision := revisions[0]
	if slices.ContainsFunc(revisions, func(other uint64) bool { return other != revision }) {
		return 0
	}
	return revision
}

func (a *App) observeFreeServiceCheck(p autonomy.Policy, s autonomy.Service, cfg config.Config, result dataplane.NodeCheckResult) {
	if result.ProbeID == "" || result.NodeID == "" || result.RoutePathID != "sing-box:"+result.NodeID || !slices.Contains(p.Protocols, "vless") {
		return
	}
	binding := freeServiceBinding(p, s, cfg)
	r := &a.nodeReadiness
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.service == nil {
		r.service = map[string]freeServiceObservation{}
	}
	own, known := r.service[result.NodeID]
	if !known && len(r.service) >= nodestore.MaxNodes {
		return
	}
	if own.consent != binding {
		own = freeServiceObservation{consent: binding}
	}
	var applied uint64
	if cfg.AppliedServices[s.ID].Enabled && selectedRoute(cfg.AppliedServices[s.ID]) == result.RoutePathID &&
		(result.ErrorCode == "node-transport-failed" || result.ErrorCode == "node-egress-failed") {
		applied = cfg.AppliedRevision
	}
	copy(own.probes[:], own.probes[1:])
	copy(own.appliedFailures[:], own.appliedFailures[1:])
	own.probes[len(own.probes)-1] = result.ProbeID
	own.appliedFailures[len(own.appliedFailures)-1] = applied
	r.service[result.NodeID] = own
}

type freeServiceReplacement struct {
	applied uint64
	consent freeServiceConsent
	route   string
}

func (a *App) freeServiceReplacements(ctx context.Context, p autonomy.Policy, services []autonomy.Service, cfg config.Config) map[string]freeServiceReplacement {
	out := map[string]freeServiceReplacement{}
	committed := a.appliedEffectiveRoutes(cfg)
	for _, s := range services {
		route := committed[s.ID]
		def, ok := a.autonomyService(s.ID)
		if !ok || !s.Enabled || s.Removing || s.Definition != autonomyDefinition(def) ||
			s.DraftFingerprint != autonomyDraftFingerprint(cfg.Services[s.ID]) || !cfg.AppliedServices[s.ID].Enabled ||
			selectedRoute(cfg.AppliedServices[s.ID]) != route || !strings.HasPrefix(route, "sing-box:node-") {
			continue
		}
		if a.autonomyResourceGuard(ctx, p, s, cfg, def) != nil {
			continue
		}
		out[s.ID] = freeServiceReplacement{cfg.AppliedRevision, freeServiceBinding(p, s, cfg), route}
	}
	return out
}

func freeNodeRemovalUntil(n nodestore.Node, snapshot nodestore.Snapshot, policy autonomy.Policy, network string, now time.Time, rotation freeRotationObservations, replacements map[string]freeServiceReplacement) time.Time {
	rows := n.Health.History // NodeStore exposes newest first.
	count := policy.EffectivePublicNodeFailureThreshold()
	if count < 2 || count > autonomy.MaxPublicNodeFailureThreshold || !exclusivelyFreeVLESS(n, policy, now) || len(rows) < count {
		return time.Time{}
	}
	last, first := rows[0], rows[count-1]
	// RAM can hold a newer general check than either durable service record.
	latest := rotation.latest[n.ID]
	history, observed := rotation.scopes[n.ID]
	if observed && (history.otherScope || history.network != network || history.engine != "sing-box" || history.passUntil.After(first.CheckedAt)) ||
		!observed && rotation.saturated || !latest.CheckedAt.IsZero() && !latest.CheckedAt.Before(last.CheckedAt) {
		return time.Time{}
	}
	replacement, ok := replacements[last.ServiceID]
	scope := rotation.service[n.ID]
	applied := scope.confirmedAppliedRevision(count)
	if !ok || scope.consent != replacement.consent || applied == 0 || replacement.applied <= applied {
		return time.Time{}
	}
	for _, c := range rows {
		if c.NetworkProfile != network || c.RoutePathID != "sing-box:"+n.ID || c.ServiceID != last.ServiceID || c.Verdict == "PASS" && c.ExpiresAt.After(first.CheckedAt) {
			return time.Time{}
		}
	}
	probes := make(map[string]bool, count)
	failureUntil := first.CheckedAt.Add(10 * time.Minute)
	for i, c := range rows[:count] {
		if c.ProbeID == "" || probes[c.ProbeID] || c.ProbeID != scope.probes[len(scope.probes)-1-i] ||
			c.CheckedAt.IsZero() || c.CheckedAt.After(now) || !c.ExpiresAt.After(now) ||
			(i > 0 && rows[i-1].CheckedAt.Sub(c.CheckedAt) < 10*time.Second) ||
			c.State != "unavailable" || c.DirectLeak || c.HTTPStatus != 0 || c.EgressIP != "" || c.Verdict != "ERROR" ||
			!(c.Stage == "transport" && c.ErrorCode == "node-transport-failed" || c.Stage == "egress" && c.ErrorCode == "node-egress-failed") {
			return time.Time{}
		}
		probes[c.ProbeID] = true
		failureUntil = minTime(failureUntil, c.ExpiresAt)
	}
	originUntil := freeOriginDeadline(n, policy, first.CheckedAt, now)
	if originUntil.IsZero() || !failureUntil.After(now) {
		return time.Time{}
	}
	for _, peer := range snapshot.Nodes {
		if replacement.route != "sing-box:"+peer.ID || peer.ID == n.ID || !allowedAutonomyNode(policy, peer, now) || len(peer.Health.History) == 0 {
			continue
		}
		p := peer.Health.History[0]
		peerScope := rotation.service[peer.ID]
		if latest := rotation.latest[peer.ID]; !latest.CheckedAt.IsZero() && !latest.CheckedAt.Before(p.CheckedAt) {
			continue
		}
		if peerScope.consent != replacement.consent || peerScope.probes[len(peerScope.probes)-1] != p.ProbeID {
			continue
		}
		if p.ServiceID == last.ServiceID && p.NetworkProfile == network && p.RoutePathID == "sing-box:"+peer.ID &&
			p.ProbeID != "" && p.Verdict == "PASS" && p.TestLevel == "service" && p.State == "available" && !p.DirectLeak &&
			p.CheckedAt.After(last.CheckedAt) && !p.CheckedAt.After(now) && p.CheckedAt.After(now.Add(-2*time.Minute)) && p.ExpiresAt.After(now) {
			peerUntil := freeOriginDeadline(peer, policy, p.CheckedAt, now)
			if nodecleanup.Eligible(n.ID, last.ServiceID, network, cleanupChecks(n), now, !peerUntil.IsZero()) {
				return minTime(minTime(originUntil, peerUntil), minTime(p.CheckedAt.Add(2*time.Minute), minTime(p.ExpiresAt, failureUntil)))
			}
		}
	}
	return time.Time{}
}

func (a *App) retireFreeNodes(ctx context.Context, p autonomy.Policy, cfg config.Config, snap nodestore.Snapshot, network string, engines map[string]bool, freePool bool, services []autonomy.Service, review func(context.Context) error) (nodestore.Snapshot, error) {
	store, nodes := a.Store, a.Nodes
	now := time.Now()
	if a.Dataplane == nil || nodes == nil || store == nil {
		return snap, nil
	}
	a.nodeReadiness.mu.Lock()
	paused := a.nodeReadiness.halted || (a.nodeReadiness.network == network && a.nodeReadiness.pausedUntil.After(now))
	a.nodeReadiness.mu.Unlock()
	if paused {
		return snap, nil
	}
	if !slices.Contains(p.Protocols, "vless") {
		return snap, nil
	}
	policy := a.nodeReadinessSourcePolicy(p, snap, true)
	if len(policy.SourceIDs) == 0 {
		return snap, nil
	}
	rotation := a.freeRotationSnapshot(snap)
	var replacements map[string]freeServiceReplacement
	var failedServices []autonomy.Service
	if !freePool && engines["sing-box"] {
		needed := map[string]bool{}
		count := policy.EffectivePublicNodeFailureThreshold()
		for _, o := range rotation.service {
			if o.consent.revision == p.Revision && o.confirmedAppliedRevision(count) != 0 {
				needed[o.consent.service] = true
			}
		}
		for _, svc := range services {
			if needed[svc.ID] {
				failedServices = append(failedServices, svc)
			}
		}
	}
	if len(failedServices) > 0 {
		checker, err := a.nodeCheckerForEngine("sing-box")
		if local, ok := checker.(interface{ RuntimeInstalled() bool }); err == nil && (!ok || local.RuntimeInstalled()) {
			replacements = a.freeServiceReplacements(ctx, p, failedServices, cfg)
		}
	}
	var ids []string
	retired := map[string]freeNodeRetirement{}
	exactService := map[string]string{}
	for _, n := range snap.Nodes {
		var until time.Time
		if freePool {
			until = rotation.deadline(n, snap, policy, network, engines, now)
		}
		if len(replacements) > 0 {
			until = freeNodeRemovalUntil(n, snap, policy, network, now, rotation, replacements)
			if until.After(now) {
				exactService[n.ID] = n.Health.History[0].ServiceID
			}
		}
		if until.After(now) {
			ids = append(ids, n.ID)
			retired[n.ID] = freeNodeRetirement{network, p.Revision, until}
		}
	}
	if len(ids) == 0 {
		return snap, nil
	}
	a.nodeReadiness.mu.Lock()
	for id, observation := range a.nodeReadiness.retired {
		if !observation.active(network, p.Revision, now) {
			delete(a.nodeReadiness.retired, id)
		}
	}
	room := nodestore.MaxNodes - len(a.nodeReadiness.retired)
	a.nodeReadiness.mu.Unlock()
	if room <= 0 {
		return snap, nil
	}
	ids = ids[:min(len(ids), room)]
	err := a.Operations.WithExclusiveContext(ctx, func() error {
		if err := review(ctx); err != nil {
			return err
		}
		currentNetwork, err := a.freshNetworkProfile(ctx)
		if err != nil {
			return err
		}
		currentPolicy := a.nodeReadinessSourcePolicy(p, snap, true)
		if currentNetwork != network || a.Store != store || a.Nodes != nodes || !reflect.DeepEqual(currentPolicy, policy) {
			return nodestore.ErrGeneration
		}
		if err := a.Dataplane.CheckExecutionRecovery(ctx); err != nil {
			return err
		}
		refs, err := a.protectedCleanupNodes(ctx, snap)
		if err != nil {
			return err
		}
		a.autonomy.mu.Lock()
		for serviceID, state := range a.autonomy.doc.Runtime {
			search := state.Search
			if search == nil || search.Exhausted {
				continue
			}
			for index, id := range search.Ordered {
				// A successfully replaced node can still occur in its own
				// automatic traversal. A separate pending service keeps its candidate.
				if index >= search.Cursor && exactService[id] != serviceID {
					refs[id] = "pending traversal"
				}
			}
		}
		a.autonomy.mu.Unlock()
		a.nodeReviews.mu.Lock()
		for _, preview := range a.nodeReviews.reviews {
			if preview.ExpiresAt.After(now) {
				refs[preview.NodeID] = "review"
			}
		}
		a.nodeReviews.mu.Unlock()
		a.reconciler.mu.Lock()
		busy := !a.reconciler.started || a.reconciler.blocked || a.reconciler.activeJobID != 0 ||
			slices.ContainsFunc(a.reconciler.doc.Jobs, func(j durableServiceJob) bool { return !j.terminal() })
		a.reconciler.mu.Unlock()
		if busy {
			return nil
		}
		ids = slices.DeleteFunc(ids, func(id string) bool { return refs[id] != "" })
		if len(ids) == 0 {
			return nil
		}

		return store.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error {
			commitAt := time.Now()
			for _, id := range ids {
				if !retired[id].until.After(commitAt) {
					return nodestore.ErrGeneration
				}
			}
			after, err := nodes.DeleteBatch(ctx, ids, snap.Generation, commitAt)
			if err == nil {
				snap = after
				a.nodeReadiness.mu.Lock()
				if a.nodeReadiness.retired == nil {
					a.nodeReadiness.retired = map[string]freeNodeRetirement{}
				}
				for _, id := range ids {
					a.nodeReadiness.retired[id] = retired[id]
					delete(a.nodeReadiness.entries, id)
				}
				a.nodeReadiness.mu.Unlock()
			}
			return err
		})
	})
	return snap, err
}
