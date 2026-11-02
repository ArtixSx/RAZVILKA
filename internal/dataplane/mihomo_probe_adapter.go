package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This registration supports a finite check only. None of the ordinary Apply
// methods can launch a child, including with a forged Ready plan.
type MihomoProbeAdapter struct {
	self          *MihomoProbeAdapter
	components    *components.Manager
	provider      *netidentity.Provider
	mu            sync.Mutex
	busy          bool
	pending       *mihomoProbeResource
	livePending   *mihomoLiveResource
	liveActive    *mihomoLiveResource
	liveProxy     *ProxyTunnelAdapter
	liveManager   *Manager
	liveOptions   *MihomoLiveOptions
	livePreparing *mihomoLivePreparation
}

func NewMihomoProbeAdapter(manager *components.Manager, provider *netidentity.Provider) *MihomoProbeAdapter {
	if manager == nil || provider == nil {
		return nil
	}
	a := &MihomoProbeAdapter{components: manager, provider: provider}
	a.self = a
	return a
}

func (*MihomoProbeAdapter) ID() string { return "mihomo" }
func (a *MihomoProbeAdapter) Snapshot(c context.Context, p Plan, s string) error {
	return a.liveSnapshot(c, p, s)
}
func (a *MihomoProbeAdapter) Stage(c context.Context, p Plan, s string) error {
	return a.liveStage(c, p, s)
}
func (a *MihomoProbeAdapter) Validate(c context.Context, p Plan, s string) error {
	return a.liveValidate(c, p, s)
}
func (a *MihomoProbeAdapter) Activate(c context.Context, p Plan, s string) error {
	return a.liveActivate(c, p, s)
}
func (a *MihomoProbeAdapter) Health(c context.Context, p Plan, s string) error {
	r, e := a.phaseResource(c, p, s)
	if e != nil {
		return e
	}
	return r.currentLive(r.resourceContext(c))
}
func (a *MihomoProbeAdapter) Commit(c context.Context, p Plan, s string) error {
	return a.liveCommit(c, p, s)
}
func (a *MihomoProbeAdapter) Rollback(c context.Context, p Plan, s string) error {
	return a.liveRollback(c, p, s)
}

// RegisteredWith is a read-only comparison of the actual registry slot, not
// a cached startup flag or a claim that the installed runtime is available.
func (a *MihomoProbeAdapter) RegisteredWith(manager *Manager) bool {
	if a == nil || a.self != a || manager == nil {
		return false
	}
	registered, ok := manager.adapter("mihomo")
	return ok && registered == a
}

type MihomoServiceProbe struct {
	ReviewSHA256    string `json:"review_sha256"`
	ConfigSHA256    string `json:"config_sha256"`
	ServiceID       string `json:"service_id"`
	NetworkProfile  string `json:"network_profile"`
	HTTPStatus      int    `json:"http_status"`
	ServiceVerified bool   `json:"service_verified"`
	CleanupVerified bool   `json:"cleanup_verified"`
	LiveApplied     bool   `json:"live_applied"`
	DurationMS      int64  `json:"duration_ms"`
}

// Pending means original custody still exists. The App must keep its original
// exclusive cleanup admission and source alive until this becomes false.
func (a *MihomoProbeAdapter) Pending() bool {
	if a == nil || a.self != a {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pending != nil
}

// RetryCleanup uses only the retained original resource and its pre-issued
// cleanup admission. The caller must still own that SAME exclusive operation;
// a new request or serialized execution cannot adopt a process.
func (a *MihomoProbeAdapter) RetryCleanup(ctx context.Context) error {
	if a == nil || a.self != a || xraySelectedTCPFinite(ctx) != nil {
		return ErrMihomoProbe
	}
	a.mu.Lock()
	if a.busy || a.pending == nil {
		a.mu.Unlock()
		return ErrMihomoProbe
	}
	r := a.pending
	a.busy = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()
	ctx = r.scope.contextWith(ctx)
	if err := r.control.CurrentForCleanupOperation(ctx, r.cleanup); err != nil {
		return err
	}
	if err := r.scope.manager.beginOperation(ctx); err != nil {
		return err
	}
	defer r.scope.manager.endOperation()
	if !r.settled {
		if err := r.clean(ctx); err != nil {
			return err
		}
	}
	// Cleanup cannot turn an earlier failed check into service evidence.
	return r.finish(ctx, nil)
}

func mihomoProbePlan(d ExecutionMihomoProbeDefinition) Plan {
	intent := d.Clone()
	intent.PlanID, intent.PlanDigest = "", ""
	digest := nodeServiceProofDigest(intent)
	return Plan{SchemaVersion: SchemaVersion, PlanID: "dp-" + digest[:16], Digest: digest, Revision: d.Revision, NetworkProfileID: d.NetworkProfile,
		State: "blocked", Adapters: []string{"mihomo"}, Blockers: []Blocker{{Code: "MIHOMO_RUNTIME_UNAVAILABLE", Adapter: "mihomo", Message: "Mihomo supports this isolated service check; a live route is not admitted."}},
		Routes: []Route{{ServiceID: d.Service.ID, LogicalServiceID: d.Service.ID, Selected: "mihomo", Resolved: "mihomo", ProbeService: &intent.Service, ProbeURL: d.Service.ProbeURL}}}
}

func validateMihomoProbePlan(p Plan) error {
	if p.Ready || p.State != "blocked" || p.SchemaVersion != SchemaVersion || p.Revision == 0 || !validPlanID(p.PlanID) || !validPlanDigest(p.Digest) || p.NetworkProfileID == "" || p.Noop || p.SafeMode ||
		p.LAN != nil || p.DNS != nil || p.DomainPolicy != nil || p.SyntheticDNS != nil || p.SuspendDNS || p.DiscardDNS || len(p.Actions) != 0 || len(p.RetiringAdapters) != 0 || len(p.ResourceConflicts) != 0 ||
		!reflect.DeepEqual(p.Adapters, []string{"mihomo"}) || len(p.Routes) != 1 || len(p.Blockers) != 1 || p.Blockers[0].Code != "MIHOMO_RUNTIME_UNAVAILABLE" || p.Blockers[0].Adapter != "mihomo" {
		return ErrMihomoProbe
	}
	r := p.Routes[0]
	if r.Resolved != "mihomo" || r.Selected != "mihomo" || len(r.CIDRs)+len(r.Domains)+len(r.Sources)+len(r.Ingress) != 0 {
		return ErrMihomoProbe
	}
	_, err := FrozenProbeService(r)
	return err
}

func (a *MihomoProbeAdapter) Check(ctx context.Context, manager *Manager, source *components.MihomoProbeSource, service catalog.Service, revision uint64, networkProfile string,
	componentHistory *updatecheck.ComponentHistoryAdmission, history *updatecheck.ExecutionHistoryAdmission, control *operationgate.ControlEpochReview) (result MihomoServiceProbe, resultErr error) {
	started := time.Now()
	if a == nil || a.self != a || manager == nil || source == nil || !source.OwnedBy(a.components) || componentHistory == nil || history == nil || control == nil || xraySelectedTCPFinite(ctx) != nil {
		return result, ErrMihomoProbe
	}
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) > 2*time.Minute {
		return result, ErrMihomoProbe
	}
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	resourceGuard, _ := ctx.Value(nodeResourceGuardKey{}).(*nodeResourceGuard)
	if guard == nil || resourceGuard == nil || resourceGuard.check == nil {
		return result, ErrMihomoProbe
	}
	a.mu.Lock()
	if a.busy || a.pending != nil {
		a.mu.Unlock()
		return result, ErrMihomoProbe
	}
	a.busy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy = false
		a.mu.Unlock()
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	if !a.RegisteredWith(manager) {
		return result, ErrMihomoProbe
	}
	if err := componentHistory.CheckReadable(ctx); err != nil {
		return result, err
	}
	requiredReader := 4
	if !source.Reference().ParentOrigin.IsZero() {
		requiredReader = 5
	}
	if err := history.CheckWrite(ctx, requiredReader); err != nil {
		return result, err
	}
	if err := control.Current(ctx); err != nil {
		return result, err
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return result, err
	}
	if err := source.Current(ctx); err != nil {
		return result, err
	}
	identity, err := a.provider.Observe(ctx)
	if err != nil {
		return result, err
	}
	frozen, err := FrozenProbeService(Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
	if err != nil {
		return result, err
	}
	d := ExecutionMihomoProbeDefinition{Schema: 1, Source: source.Reference(), Service: frozen, Revision: revision, NetworkProfile: networkProfile, NetworkIdentity: identity}
	p := mihomoProbePlan(d)
	d.PlanID, d.PlanDigest = p.PlanID, p.Digest
	if d.validate() != nil || validateMihomoProbePlan(p) != nil {
		return result, ErrMihomoProbe
	}
	if err := verifyNetworkProfile(ctx, networkProfile, manager.FreshProfile); err != nil {
		return result, err
	}
	if err := checkNodeResource(ctx, d.Source.ServerHost, d.Source.Endpoint); err != nil {
		return result, err
	}
	if err := observeMihomoProbeListenerAbsent(ctx, a.provider, identity, d.Source.SOCKSPort); err != nil {
		return result, err
	}
	if err := manager.beginOperation(ctx); err != nil {
		return result, err
	}
	defer manager.endOperation()
	var resource *mihomoProbeResource
	err = manager.withExecutionResourcesModesLocked(ctx, p, "mihomo", func(held context.Context) error {
		var err error
		resource, err = a.issueProbe(held, source, control, cleanup, d)
		if err != nil {
			return err
		}
		return resource.run(held)
	}, false, true)
	if err != nil || resource == nil || a.Pending() {
		return result, errors.Join(err, ErrMihomoProbe)
	}
	if err := errors.Join(guard(ctx), nodeResourceRefusal(ctx), control.Current(ctx), componentHistory.CheckReadable(ctx)); err != nil {
		return result, err
	}
	result = resource.result
	result.CleanupVerified = true
	return result, nil
}

func mihomoProbeEndpoint(port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

// Always include the primary scenario, then every other mandatory catalog
// scenario. Optional primary remains useful, but cannot replace a required one.
func mihomoRequiredProbes(service catalog.Service) []catalog.Probe {
	primary := probecheck.ServiceProbe(service)
	probes := []catalog.Probe{primary}
	for _, probe := range service.Probes {
		if probe.Required && probe.ID != primary.ID {
			probes = append(probes, probe)
		}
	}
	return probes
}
