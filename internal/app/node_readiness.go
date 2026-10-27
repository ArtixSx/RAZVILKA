package app

import (
	"context"
	"fmt"
	"hash/fnv"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// The readiness pool walks the nodes the autopilot may use and runs the
// existing general HTTPS connectivity check (runNodeConnectivity: paired
// egress control, no service proof) on one node at a time, so working nodes
// are known before a service needs one. Its memory is RAM-only and orders the
// pending candidates of a service search; it never proves a service, never
// applies a route, never deletes a node, never records a CandidateFailure and
// never ranks a source. A restart forgets it.
const (
	nodeReadinessWarm         = 3                // fresh PASS nodes kept per engine
	nodeReadinessHourlyChecks = 60               // rotation checks per rolling hour
	nodeReadinessSpacing      = 30 * time.Second // between rotation checks and after any recorded node check
	nodeReadinessNodeSpacing  = 10 * time.Minute // between any two checks of one node
	nodeReadinessRecheck      = 10 * time.Minute // a PASS or a first failure is checked again after this
	nodeReadinessJitter       = 2 * time.Minute
	nodeReadinessFresh        = 15 * time.Minute // how long a PASS moves a node ahead
	nodeReadinessUnknownDelay = 20 * time.Minute // a check that says nothing about the node
	nodeReadinessBackoff      = 20 * time.Minute // after the second failure in a row; doubles
	nodeReadinessDeadBackoff  = 2 * time.Hour    // after the second TCP connect failure in a row; doubles
	nodeReadinessMaxBackoff   = 6 * time.Hour
	nodeReadinessControlFresh = 10 * time.Minute // a TCP failure counts only after a recent measured direct control
	nodeReadinessWANPause     = 5 * time.Minute
	nodeReadinessShortPause   = time.Minute
	nodeReadinessEngineTTL    = time.Hour
	nodeReadinessEngineReads  = 4 // material reads per round to learn unknown engines
)

type nodeReadinessEntry struct {
	Engine      string
	EngineAt    time.Time
	CheckedAt   time.Time // last rotation observation of this node
	PassAt      time.Time
	Ready       bool // the last observation was a PASS
	Failures    int  // definite failures in a row, each at least NodeSpacing after the previous
	Transport   int  // trailing TCP connect failures among them
	LastFailure time.Time
	Next        time.Time
	Received    time.Time // freshest permitted origin; a newer one resets the backoff
}

func (e nodeReadinessEntry) ready(now time.Time) bool {
	return e.Ready && !e.PassAt.IsZero() && !e.PassAt.After(now) && now.Sub(e.PassAt) < nodeReadinessFresh
}

// failing needs two failures in a row: one failure leaves a node uncertain,
// because working nodes drop a share of new connections.
func (e nodeReadinessEntry) failing(now time.Time) bool {
	return e.Failures >= 2 && !e.LastFailure.After(now) && now.Sub(e.LastFailure) < nodeReadinessMaxBackoff
}

type nodeReadinessState struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	engineSet   string
	network     string
	cursor      string
	entries     map[string]nodeReadinessEntry
	checks      []time.Time // rotation check starts within the last hour
	lastCheck   time.Time
	pausedUntil time.Time
	halted      bool // a check did not finish its cleanup; stays until restart
	controlAt   time.Time
	state       string
}

type nodeReadinessOutcome int

const (
	nodeReadinessUnknown   nodeReadinessOutcome = iota // the node was contacted; nothing definite
	nodeReadinessPass                                  // general HTTPS through the node, direct control measured
	nodeReadinessEgress                                // node-egress-failed with a measured direct control
	nodeReadinessTransport                             // TCP connect to the node failed
	nodeReadinessNetwork                               // WAN, direct control or network not confirmed
	nodeReadinessNotRun                                // no network work happened (dispatcher busy, no checker)
	nodeReadinessCleanup                               // temporary runtime cleanup not confirmed
	nodeReadinessUnusable                              // this material or engine cannot be checked here
	nodeReadinessRefused                               // the user's exclusions refused the check
)

func nodeReadinessOutcomeOf(item nodeCheckItem) nodeReadinessOutcome {
	if item.ErrorCode == "node-cleanup-failed" || item.Stage == "cleanup" {
		return nodeReadinessCleanup
	}
	if item.ConnectivityReady && item.CleanupVerified && item.TestLevel == "connectivity" && item.Stage == "connectivity" && item.Verdict == "PASS" && item.ErrorCode == "" && item.DirectControl == "measured" {
		return nodeReadinessPass
	}
	switch item.ErrorCode {
	case "node-check-busy", "node-check-unavailable", "node-checker-unavailable":
		return nodeReadinessNotRun
	case "node-egress-control-unavailable", "node-direct-control-unavailable", "node-network-changed":
		return nodeReadinessNetwork
	case "node-resource-refused":
		return nodeReadinessRefused
	case "node-runtime-unsupported", "node-config-invalid", "node-runtime-config-rejected":
		return nodeReadinessUnusable
	case "node-egress-failed":
		if item.Stage == "egress" && item.Verdict == "ERROR" && item.DirectControl == "measured" && item.CleanupVerified {
			return nodeReadinessEgress
		}
	case "node-transport-failed":
		if item.Stage == "transport" && item.Verdict == "ERROR" && item.DirectControl == "not_run" && item.CleanupVerified {
			return nodeReadinessTransport
		}
	}
	return nodeReadinessUnknown
}

// The jitter is derived from the node and time, so nodes checked together
// drift apart without a random source.
func nodeReadinessJitterFor(id string, at time.Time) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	_, _ = h.Write([]byte(at.UTC().Format(time.RFC3339)))
	return time.Duration(h.Sum32()%uint32(nodeReadinessJitter/time.Second+1)) * time.Second
}

func nodeReadinessDelay(e nodeReadinessEntry) time.Duration {
	if e.Failures < 2 {
		return nodeReadinessRecheck
	}
	delay, steps := nodeReadinessBackoff, e.Failures-2
	if e.Transport >= 2 {
		delay, steps = nodeReadinessDeadBackoff, e.Transport-2
	}
	for ; steps > 0 && delay < nodeReadinessMaxBackoff; steps-- {
		delay *= 2
	}
	return min(delay, nodeReadinessMaxBackoff)
}

// observeLocked records one rotation check made at `at`. Only the node's own
// schedule changes, except that WAN-wide outcomes pause the whole rotation.
func (r *nodeReadinessState) observeLocked(id string, item nodeCheckItem, at time.Time) {
	outcome := nodeReadinessOutcomeOf(item)
	if outcome == nodeReadinessNotRun || item.ErrorCode == "node-check-canceled" {
		// Stop or shutdown interrupted it: no observation of the node.
		return
	}
	if outcome == nodeReadinessCleanup {
		r.halted = true
		return
	}
	e := r.entries[id]
	if item.Engine != "" {
		e.Engine, e.EngineAt = item.Engine, at
	}
	controlled := !r.controlAt.IsZero() && !r.controlAt.After(at) && at.Sub(r.controlAt) < nodeReadinessControlFresh
	if item.CleanupVerified && item.DirectControl == "measured" {
		r.controlAt = at
	}
	if outcome == nodeReadinessTransport && !controlled {
		// Without a recent measured direct control a refused TCP connect may be
		// our own uplink. Never count it against the node; wait a little.
		outcome = nodeReadinessNetwork
	}
	e.CheckedAt = at
	switch outcome {
	case nodeReadinessPass:
		e.Ready, e.PassAt = true, at
		e.Failures, e.Transport, e.LastFailure = 0, 0, time.Time{}
		e.Next = at.Add(nodeReadinessRecheck + nodeReadinessJitterFor(id, at))
	case nodeReadinessEgress, nodeReadinessTransport:
		e.Ready = false
		if e.LastFailure.IsZero() || at.Sub(e.LastFailure) >= nodeReadinessNodeSpacing {
			e.Failures = min(e.Failures+1, 32)
			if outcome == nodeReadinessTransport {
				e.Transport = min(e.Transport+1, 32)
			} else {
				e.Transport = 0
			}
			e.LastFailure = at
		}
		e.Next = at.Add(nodeReadinessDelay(e) + nodeReadinessJitterFor(id, at))
	case nodeReadinessNetwork:
		pause := nodeReadinessWANPause
		if item.ErrorCode == "node-network-changed" || item.ErrorCode == "node-transport-failed" {
			pause = nodeReadinessShortPause
		}
		r.pausedUntil = at.Add(pause)
		e.Next = at.Add(nodeReadinessNodeSpacing + nodeReadinessJitterFor(id, at))
	case nodeReadinessUnusable:
		e.Ready = false
		e.Next = at.Add(nodeReadinessMaxBackoff)
	case nodeReadinessRefused:
		e.Ready = false
		e.Next = at.Add(nodeReadinessEngineTTL)
	default:
		e.Ready = false
		e.Next = at.Add(nodeReadinessUnknownDelay + nodeReadinessJitterFor(id, at))
	}
	r.entries[id] = e
}

// nodeReadinessEngines lists the engines some enrolled service could use for a
// node route, limited to engines whose checker runs the connectivity check.
func (a *App) nodeReadinessEngines(p autonomy.Policy, cfg config.Config, services []autonomy.Service) map[string]bool {
	engines := map[string]bool{}
	if len(p.SourceIDs) == 0 || len(p.Protocols) == 0 {
		return engines
	}
	definitions := map[string]catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		definitions[service.ID] = service
	}
	for _, s := range services {
		service, known := definitions[s.ID]
		if !s.Enabled || s.Removing || !cfg.Services[s.ID].Enabled || !known || autonomyDomainService(service) || !serviceHasNodeProbe(service) || catalog.IsNFQWS2Starter(service) && s.ExpectedRoute == "nfqws2" {
			continue
		}
		if s.ExpectedRoute == "auto" {
			// AUTO uses an Xray node only with the owner's route preference.
			engines["sing-box"] = true
			engines["xray"] = engines["xray"] || slices.Contains(p.PreferredRoutes, "xray")
			continue
		}
		engines[autonomyNodeEngine(s.ExpectedRoute)] = true
	}
	for engine, wanted := range engines {
		checker, err := a.nodeCheckerForEngine(engine)
		if _, ok := checker.(dataplane.NodeConnectivityChecker); !wanted || err != nil || !ok {
			delete(engines, engine)
		}
	}
	return engines
}

func (a *App) setNodeReadinessState(state string) {
	a.nodeReadiness.mu.Lock()
	a.nodeReadiness.state = state
	a.nodeReadiness.mu.Unlock()
}

// nodeReadinessRound runs at most one connectivity check, on the reconciler's
// existing feeds cadence and inside its own exclusive admission, so no user
// operation, durable job or other check runs at the same time. It never waits
// for admission or for the shared dispatcher quota.
func (a *App) nodeReadinessRound(parent context.Context, now time.Time) {
	if a == nil || parent == nil || parent.Err() != nil || a.Store == nil || a.Nodes == nil || now.IsZero() {
		return
	}
	// One check may take a minute; never start it at the end of the budget.
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) < time.Minute {
		return
	}
	if a.hasDueRuntimeStop(now) || a.componentMaintenancePending() {
		a.setNodeReadinessState("idle")
		return
	}
	ctx, release, err := a.scopedRuntimeOperation(parent)
	if err != nil {
		return
	}
	defer release()
	a.autonomy.mu.Lock()
	loaded := a.autonomy.loaded && !a.autonomy.blocked
	p := autonomy.Clone(a.autonomy.doc.Policy)
	services := make([]autonomy.Service, 0, len(a.autonomy.doc.Services))
	for _, s := range a.autonomy.doc.Services {
		services = append(services, s)
	}
	a.autonomy.mu.Unlock()
	cfg := a.Store.Get()
	if !loaded || !p.SetupComplete || !p.Enabled || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
		a.setNodeReadinessState("idle")
		return
	}
	engines := a.nodeReadinessEngines(p, cfg, services)
	if len(engines) == 0 {
		a.setNodeReadinessState("idle")
		return
	}
	permissionsCurrentLocked := func() bool {
		valid := a.autonomy.loaded && !a.autonomy.blocked && reflect.DeepEqual(a.autonomy.doc.Policy, p) && len(a.autonomy.doc.Services) == len(services)
		for _, old := range services {
			current, ok := a.autonomy.doc.Services[old.ID]
			valid = valid && ok && reflect.DeepEqual(current, old)
		}
		return valid
	}
	review := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		a.autonomy.mu.Lock()
		valid := permissionsCurrentLocked()
		a.autonomy.mu.Unlock()
		if !valid || a.autonomyDiskCurrent(c) != nil {
			return dataplane.ErrReviewChanged
		}
		return nil
	}
	if review(ctx) != nil {
		return
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		a.setNodeReadinessState("paused-network")
		return
	}
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil {
		return
	}
	// Any recorded check counts: service, engine, connectivity or TCP.
	lastAny, latest := map[string]time.Time{}, time.Time{}
	seen := func(id string, at time.Time) {
		if at.After(lastAny[id]) {
			lastAny[id] = at
		}
		if at.After(latest) {
			latest = at
		}
	}
	ids, received := []string{}, map[string]time.Time{}
	sourcePolicy := a.nodeReadinessSourcePolicy(p, snapshot)
	for _, n := range snapshot.Nodes {
		seen(n.ID, n.Health.CheckedAt)
		for _, c := range n.Health.History {
			seen(n.ID, c.CheckedAt)
		}
		if allowedAutonomyNode(sourcePolicy, n, now) {
			ids = append(ids, n.ID)
			for _, o := range n.Origins {
				if slices.Contains(p.SourceIDs, o.SourceID) && !now.Before(o.ReceivedAt) && now.Before(o.ExpiresAt) && o.ReceivedAt.After(received[n.ID]) {
					received[n.ID] = o.ReceivedAt
				}
			}
		}
	}
	a.nodeChecks.mu.Lock()
	for id, item := range a.nodeChecks.connectivity {
		seen(id, item.CheckedAt)
	}
	for id, item := range a.nodeChecks.pings {
		seen(id, item.CheckedAt)
	}
	a.nodeChecks.mu.Unlock()
	slices.Sort(ids)

	r := &a.nodeReadiness
	r.mu.Lock()
	engineNames := []string{}
	for engine := range engines {
		engineNames = append(engineNames, engine)
	}
	slices.Sort(engineNames)
	engineSet := strings.Join(engineNames, ",")
	if r.network != profile || r.entries == nil || r.engineSet != engineSet {
		r.engineSet = engineSet
		// Results describe one network only.
		r.network, r.cursor, r.entries, r.controlAt, r.pausedUntil = profile, "", map[string]nodeReadinessEntry{}, time.Time{}, time.Time{}
	}
	r.checks = slices.DeleteFunc(r.checks, func(at time.Time) bool { return now.Sub(at) >= time.Hour })
	for id := range r.entries {
		if _, ok := slices.BinarySearch(ids, id); !ok {
			delete(r.entries, id)
		}
	}
	readyCount, present, unknown := map[string]int{}, map[string]bool{}, false
	for _, id := range ids {
		e := r.entries[id]
		if received[id].After(e.Received) {
			if !e.CheckedAt.IsZero() {
				// The feed delivered the node again: start its schedule over.
				e.Failures, e.Transport, e.LastFailure, e.Next = 0, 0, time.Time{}, time.Time{}
			}
			e.Received = received[id]
		}
		r.entries[id] = e
		// A failed engine resolution is known, not unknown: it needs no engine.
		present[e.Engine], unknown = true, unknown || e.Engine == "" && e.EngineAt.IsZero()
		if e.ready(now) {
			readyCount[e.Engine]++
		}
	}
	// Warm: every usable engine some permitted node may need has K fresh
	// PASS nodes. An engine no node uses cannot hold exploration open.
	warm := true
	for engine := range engines {
		warm = warm && (readyCount[engine] >= nodeReadinessWarm || !present[engine] && !unknown)
	}
	switch {
	case r.halted:
		r.state = "stopped"
	case len(ids) == 0:
		r.state = "empty"
	case now.Before(r.pausedUntil):
		r.state = "paused-network"
	case len(r.checks) >= nodeReadinessHourlyChecks:
		r.state = "limited"
	case warm:
		r.state = "warm"
	default:
		r.state = "running"
	}
	quiet := (r.lastCheck.IsZero() || now.Sub(r.lastCheck) >= nodeReadinessSpacing) && (latest.IsZero() || now.Sub(latest) >= nodeReadinessSpacing)
	if r.state != "running" && r.state != "warm" || !quiet {
		r.mu.Unlock()
		return
	}
	previousCursor := r.cursor
	start := 0
	if i, found := slices.BinarySearch(ids, r.cursor); found {
		start = i + 1
	} else {
		start = i
	}
	order := append(slices.Clone(ids[start:]), ids[:start]...)
	entries := map[string]nodeReadinessEntry{}
	for _, id := range order {
		entries[id] = r.entries[id]
	}
	r.mu.Unlock()

	chosen, reads, learned := "", 0, map[string]nodeReadinessEntry{}
	for _, id := range order {
		e := entries[id]
		last := lastAny[id]
		if e.CheckedAt.After(last) {
			last = e.CheckedAt
		}
		if now.Before(e.Next) || now.Sub(last) < nodeReadinessNodeSpacing {
			continue
		}
		// With enough warm nodes for every engine only those are kept warm;
		// unchecked nodes need no material read then.
		if warm && !e.ready(now) {
			continue
		}
		if e.Engine == "" || now.Sub(e.EngineAt) >= nodeReadinessEngineTTL || e.EngineAt.After(now) {
			if reads >= nodeReadinessEngineReads {
				continue
			}
			reads++
			// The same choice runNodeConnectivity makes; a local material read.
			base := "sing-box"
			if !engines[base] {
				base = "xray"
			}
			engine, err := a.compatibleNodeEngine(ctx, base, id)
			if ctx.Err() != nil {
				return
			}
			e.Engine, e.EngineAt = engine, now
			if err != nil {
				e.Engine, e.Next = "", now.Add(nodeReadinessNodeSpacing)
				if err == dataplane.ErrExactNodeUnsupported {
					e.Next = now.Add(nodeReadinessEngineTTL)
				}
				learned[id] = e
				continue
			}
			learned[id] = e
		}
		if !engines[e.Engine] {
			continue
		}
		// With enough warm nodes for this engine only those are kept warm.
		if readyCount[e.Engine] >= nodeReadinessWarm && !e.ready(now) {
			continue
		}
		chosen = id
		break
	}
	r.mu.Lock()
	if r.network != profile {
		r.mu.Unlock()
		return
	}
	for id, e := range learned {
		if current, ok := r.entries[id]; ok {
			current.Engine, current.EngineAt = e.Engine, e.EngineAt
			if e.Next.After(current.Next) {
				current.Next = e.Next
			}
			r.entries[id] = current
		}
	}
	if chosen == "" {
		r.mu.Unlock()
		return
	}
	r.cursor, r.lastCheck = chosen, now
	r.checks = append(r.checks, now)
	r.mu.Unlock()

	selectedEngine := entries[chosen].Engine
	if e, ok := learned[chosen]; ok {
		selectedEngine = e.Engine
	}
	checkCtx, cancelCheck := context.WithCancel(ctx)
	r.mu.Lock()
	r.cancel = cancelCheck
	r.mu.Unlock()
	defer func() { cancelCheck(); r.mu.Lock(); r.cancel = nil; r.mu.Unlock() }()
	consent := func(c context.Context) error {
		if err := review(c); err != nil {
			return err
		}
		snapshot, err := a.Nodes.Snapshot(c, time.Now())
		if err != nil {
			return err
		}
		sourcePolicy := a.nodeReadinessSourcePolicy(p, snapshot)
		for _, n := range snapshot.Nodes {
			if n.ID == chosen && allowedAutonomyNode(sourcePolicy, n, time.Now()) {
				return nil
			}
		}
		return dataplane.ErrReviewChanged
	}
	if consent(checkCtx) != nil {
		r.mu.Lock()
		r.state = "idle"
		r.mu.Unlock()
		return
	}
	item := a.runNodeConnectivityWithReview(checkCtx, chosen, profile, selectedEngine, consent)
	// Cancellation/revocation is not a node failure, even with a test checker
	// that never invokes the intermediate resource guard. Preserve cleanup fencing.
	revoked := consent(checkCtx) != nil

	// Serialize acceptance with permission persistence, closing the gap between
	// the final review and publishing readiness. No IO occurs under these locks.
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	revoked = revoked || checkCtx.Err() != nil || !permissionsCurrentLocked()
	r.mu.Lock()
	defer r.mu.Unlock()
	if nodeReadinessOutcomeOf(item) == nodeReadinessNotRun && len(r.checks) > 0 {
		// Nothing reached the network: keep the node next in turn and do not
		// use the hourly budget. The spacing still applies.
		r.checks = r.checks[:len(r.checks)-1]
		r.cursor = previousCursor
	}
	if r.network != profile {
		return
	}
	if revoked && nodeReadinessOutcomeOf(item) != nodeReadinessCleanup {
		if e, ok := r.entries[chosen]; ok {
			e.Ready = false
			r.entries[chosen] = e
		}
		r.state = "idle"
		return
	}
	if _, ok := r.entries[chosen]; ok {
		r.observeLocked(chosen, item, now)
	}
	if r.halted {
		r.state = "stopped"
	} else if now.Before(r.pausedUntil) {
		r.state = "paused-network"
	}
}

// nodeReadinessOrder moves nodes with a fresh connectivity PASS ahead and
// nodes after repeated failures behind. Every node stays, and the relative
// order inside each group is kept. A hint only: the search still checks each
// candidate afresh, and reading never changes the pool.
func (a *App) nodeReadinessOrder(ids []string, engine, network string, anyEngine bool, now time.Time) []string {
	r := &a.nodeReadiness
	r.mu.Lock()
	defer r.mu.Unlock()
	if network == "" || r.network != network || len(r.entries) == 0 {
		return ids
	}
	tier := map[string]int{}
	for _, id := range ids {
		e, ok := r.entries[id]
		if !ok || !anyEngine && e.Engine != engine {
			continue
		}
		switch {
		case e.ready(now):
			tier[id] = -1
		case e.failing(now):
			tier[id] = 1
		}
	}
	ordered := slices.Clone(ids)
	sort.SliceStable(ordered, func(i, j int) bool { return tier[ordered[i]] < tier[ordered[j]] })
	return ordered
}

type nodeReadinessView struct {
	State      string `json:"state"`
	Ready      int    `json:"ready"`
	BackingOff int    `json:"backing_off"`
	Unchecked  int    `json:"unchecked"`
	Total      int    `json:"total"`
	Message    string `json:"message"`
}

// nodeReadinessSnapshot is a small read-only status for the panel. It reads
// RAM only and never starts a check.
func (a *App) nodeReadinessSnapshot(now time.Time) nodeReadinessView {
	r := &a.nodeReadiness
	r.mu.Lock()
	defer r.mu.Unlock()
	view := nodeReadinessView{State: r.state}
	if view.State == "" {
		view.State = "idle"
	}
	for _, e := range r.entries {
		view.Total++
		switch {
		case e.CheckedAt.IsZero():
			view.Unchecked++
		case e.ready(now):
			view.Ready++
		case e.failing(now):
			view.BackingOff++
		}
	}
	messages := map[string]string{
		"idle":           "Заранее узлы не проверяются: автопилоту они сейчас не нужны или он на паузе.",
		"empty":          "Нет разрешённых узлов для проверки.",
		"running":        "Узлы проверяются заранее, по одному и с паузами.",
		"warm":           "Готовых узлов достаточно; повторно проверяются только они.",
		"limited":        "Достигнут часовой лимит фоновых проверок; продолжим позже.",
		"paused-network": "Фоновая проверка узлов на паузе: интернет-соединение роутера не подтверждено.",
		"stopped":        "Фоновая проверка узлов остановлена до перезапуска: временная проверка не завершилась чисто.",
	}
	view.Message = messages[view.State]
	if view.State != "idle" && view.Total > 0 {
		view.Message += fmt.Sprintf(" Готовы: %d. Отложены после сбоев: %d. Ещё не проверены: %d.", view.Ready, view.BackingOff, view.Unchecked)
	}
	return view
}

// Permission writers call this outside autonomy.mu; runtime evidence writes do not.
func (a *App) cancelNodeReadiness() {
	a.nodeReadiness.mu.Lock()
	cancel := a.nodeReadiness.cancel
	a.nodeReadiness.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// A saved origin does not keep a disabled/deleted subscription authorized.
// Manual/file origins retain their ordinary explicit policy membership.
func (a *App) nodeReadinessSourcePolicy(p autonomy.Policy, snapshot nodestore.Snapshot) autonomy.Policy {
	active := map[string]bool{}
	if a.NodeFeeds != nil {
		for _, source := range a.NodeFeeds.List() {
			active[source.SourceID] = source.Enabled
		}
	}
	feeds := map[string]bool{}
	for _, source := range snapshot.Sources {
		if source.Kind == "community" || source.Kind == "subscription" {
			feeds[source.ID] = true
		}
	}
	p.SourceIDs = slices.Clone(p.SourceIDs)
	p.SourceIDs = slices.DeleteFunc(p.SourceIDs, func(id string) bool { return feeds[id] && !active[id] })
	return p
}
