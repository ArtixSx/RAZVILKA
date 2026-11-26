package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

// The finite checker owns a listener separate from the installed live route.
// The existing adapter refuses an occupied listener before starting a child.
const mihomoStoredProbePort = 18084

type mihomoStoredProbeSource struct {
	self    *mihomoStoredProbeSource
	app     *App
	store   *nodestore.Store
	node    *dataplane.NodeDefaultSourceReview
	expires time.Time
}

func (a *App) reviewMihomoStoredProbe(ctx context.Context, nodeID string) (*mihomoStoredProbeSource, error) {
	if a == nil || a.Nodes == nil {
		return nil, dataplane.ErrNodeDefaultSource
	}
	store := a.Nodes
	now := time.Now()
	snapshot, err := store.Snapshot(ctx, now)
	if err != nil {
		return nil, errors.Join(dataplane.ErrNodeDefaultSource, err)
	}
	expires := mihomoPersonalOriginExpiry(snapshot, nodeID, now)
	if expires.IsZero() {
		return nil, dataplane.ErrNodeDefaultSource
	}
	node, err := dataplane.ReviewNodeDefaultSource(ctx, store, "mihomo:"+nodeID)
	if err != nil || a.Nodes != store || node.Reference().NodeGeneration != snapshot.Generation {
		return nil, errors.Join(dataplane.ErrNodeDefaultSource, err)
	}
	source := &mihomoStoredProbeSource{app: a, store: store, node: node, expires: expires}
	source.self = source
	return source, nil
}

func mihomoPersonalOriginExpiry(snapshot nodestore.Snapshot, id string, now time.Time) time.Time {
	personal := make(map[string]bool, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		if source.PersonalProfile() {
			personal[source.ID] = true
		}
	}
	var expires time.Time
	for _, node := range snapshot.Nodes {
		if node.ID != id || node.Disabled {
			continue
		}
		for _, origin := range node.Origins {
			if personal[origin.SourceID] && !now.Before(origin.ReceivedAt) && now.Before(origin.ExpiresAt) && origin.ExpiresAt.After(expires) {
				expires = origin.ExpiresAt
			}
		}
		break
	}
	return expires
}

func (s *mihomoStoredProbeSource) current(ctx context.Context, a *App) error {
	if s == nil || s.self != s || s.app != a || s.store == nil || s.node == nil || a == nil || a.Nodes != s.store || !time.Now().Before(s.expires) {
		return dataplane.ErrNodeDefaultSource
	}
	return s.node.Current(ctx)
}

func (s *mihomoStoredProbeSource) profile(ctx context.Context, a *App) ([]byte, error) {
	if err := s.current(ctx, a); err != nil {
		return nil, err
	}
	var raw []byte
	err := s.node.WithMaterial(ctx, func(material []byte) error {
		profile, err := providerprofile.VLESSProfileFromJSON(material)
		if err != nil || profile.Transport != "tcp" || profile.Security != "tls" || profile.Insecure {
			return errMihomoNodeScope
		}
		raw, err = json.Marshal(struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}{Outbounds: []json.RawMessage{material}})
		return err
	})
	if err != nil || a.Nodes != s.store {
		clear(raw)
		return nil, errors.Join(dataplane.ErrNodeDefaultSource, err)
	}
	return raw, nil
}

// Raw HTTP and stored material are separate inputs. A raw profile, digest or
// listener option must never replace any part of a stored candidate.
type mihomoProbeInput struct {
	raw     string
	options backendprofile.MihomoOptions
	review  string
	stored  *mihomoStoredProbeSource
}

func (p mihomoProbeInput) current(ctx context.Context, a *App) error {
	if p.stored == nil {
		return ctx.Err()
	}
	if p.raw != "" || p.options != (backendprofile.MihomoOptions{}) || p.review != "" {
		return dataplane.ErrNodeDefaultSource
	}
	return p.stored.current(ctx, a)
}

func (p mihomoProbeInput) openSource(ctx context.Context, a *App, env *mihomoProbeEnvironment, control *operationgate.ControlEpochReview, publishOrigin bool) (*components.MihomoProbeSource, error) {
	if err := p.current(ctx, a); err != nil {
		return nil, err
	}
	raw, options, review := p.raw, p.options, p.review
	if p.stored != nil {
		material, err := p.stored.profile(ctx, a)
		if err != nil {
			return nil, err
		}
		defer clear(material)
		raw = string(material)
		options.SOCKSPort = mihomoStoredProbePort
	}
	compiled, err := backendprofile.Mihomo(raw, options)
	if err != nil || options.Index < 0 || options.Index >= len(compiled.Source.Nodes) {
		return nil, errors.Join(components.ErrMihomoNativeValidation, err)
	}
	if p.stored != nil {
		digest := sha256.Sum256([]byte(compiled.Config))
		review = hex.EncodeToString(digest[:])
	}
	host := compiled.Source.Nodes[options.Index].Server
	endpoint, err := env.endpoint(ctx, host)
	if err != nil {
		return nil, err
	}
	baseGuard := a.hevForwardGuard(env.cfg, control)
	guard := baseGuard
	if p.stored != nil {
		guard = func(c context.Context, effect func() error) error {
			if err := p.current(c, a); err != nil {
				return err
			}
			return baseGuard(c, effect)
		}
	}
	if publishOrigin {
		return a.Components.ReviewMihomoProbe(ctx, raw, options, review, host, endpoint, guard)
	}
	return a.Components.ReviewMihomoProbeLegacy(ctx, raw, options, review, host, endpoint, guard)
}

func (p mihomoProbeInput) guard(ctx context.Context, a *App, env *mihomoProbeEnvironment) context.Context {
	if p.stored == nil {
		ctx = dataplane.WithReviewGuard(ctx, env.current)
		return dataplane.WithNodeResourceGuard(ctx, env.resource)
	}
	ctx = dataplane.WithReviewGuard(ctx, func(c context.Context) error {
		return errors.Join(env.current(c), p.current(c, a))
	})
	return dataplane.WithNodeResourceGuard(ctx, func(c context.Context, host string, address netip.Addr) error {
		return errors.Join(env.resource(c, host, address), p.current(c, a))
	})
}

// This result belongs to the original Store review. It is finite service
// evidence only, with no route, generic node history or Apply authority.
type mihomoStoredProbeEvidence struct {
	source *mihomoStoredProbeSource
	probe  dataplane.MihomoServiceProbe
}

func (a *App) checkMihomoStoredProbe(ctx context.Context, cfg config.Config, service catalog.Service, source *mihomoStoredProbeSource) (mihomoStoredProbeEvidence, error) {
	var evidence mihomoStoredProbeEvidence
	if a == nil || ctx == nil {
		return evidence, operationgate.ErrBusy
	}
	scope, scoped := ctx.Value(operationContextKey{}).(*operationScope)
	if !scoped || scope == nil || scope.app != a {
		return evidence, operationgate.ErrBusy
	}
	if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
		return evidence, err
	}
	if err := source.current(ctx, a); err != nil {
		return evidence, err
	}
	input := mihomoProbeInput{stored: source}
	outcome := a.runMihomoProbe(ctx, cfg, service, input, &mihomoProbeAttemptTiming{started: time.Now()})
	if outcome.pending {
		return evidence, errors.Join(outcome.err, components.ErrMihomoProbePending)
	}
	if outcome.err != nil {
		return evidence, outcome.err
	}
	if outcome.probe.ServiceID != service.ID || !outcome.probe.ServiceVerified || !outcome.probe.CleanupVerified || outcome.probe.LiveApplied {
		return evidence, dataplane.ErrMihomoProbe
	}
	return mihomoStoredProbeEvidence{source: source, probe: outcome.probe}, nil
}

func (a *App) probeStoredMihomo(w http.ResponseWriter, r *http.Request, nodeID, serviceID string, revision, generation uint64) {
	bounded, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	ctx, closeRequest, err := a.scopedRuntimeOperation(bounded)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer closeRequest()
	store := a.Store
	if store == nil {
		writeMihomoProbeFailure(w, false)
		return
	}
	cfg := store.Get()
	if cfg.Revision != revision {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "MIHOMO_REVIEW_CHANGED", "error": "Настройки изменились. Обновите сервис и профиль.", "live_applied": false})
		return
	}
	var service catalog.Service
	definition := mihomoNodeCatalogClone(a.catalogSnapshot())
	for _, candidate := range definition.Services {
		if candidate.ID == serviceID {
			service = defaultRouteCloneCatalogService(candidate)
			break
		}
	}
	source, err := a.reviewMihomoStoredProbe(ctx, nodeID)
	if err != nil || source.node.Reference().NodeGeneration != generation {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "MIHOMO_STORED_PROFILE_UNAVAILABLE", "error": "Обновите список и выберите доступный личный профиль.", "live_applied": false})
		return
	}
	verified, err := a.checkMihomoStoredProbe(ctx, cfg, service, source)
	if err != nil || ctx.Err() != nil || !a.Security.Authenticated(r) {
		writeMihomoProbeFailure(w, errors.Is(err, components.ErrMihomoProbePending))
		return
	}
	// The nested checker has joined its original resources, but the outer
	// operation is still held until this response is published.
	if a.Store != store || !reflect.DeepEqual(definition, a.catalogSnapshot()) ||
		a.nodeResourceExclusionAdmission(ctx, cfg, service, "", netip.Addr{}) != nil ||
		verified.source.current(ctx, a) != nil || !a.Security.Authenticated(r) {
		writeMihomoProbeFailure(w, false)
		return
	}
	ref := verified.source.node.Reference()
	writeJSON(w, http.StatusOK, map[string]any{
		"probe": map[string]any{
			"node_id": ref.NodeID, "node_generation": ref.NodeGeneration, "service_id": verified.probe.ServiceID,
			"network_profile": verified.probe.NetworkProfile, "http_status": verified.probe.HTTPStatus,
			"duration_ms": verified.probe.DurationMS, "service_verified": true, "cleanup_verified": true, "live_applied": false,
		},
		"live_applied": false, "draft_persisted": false, "recovery_required": false,
	})
}
