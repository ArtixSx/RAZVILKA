package app

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Same-job source captured before fetch. Neither HTTP fields nor a later
// catalogue read may substitute its original config, definition or lifetime.
type legacyManualCandidateSource struct {
	self     *legacyManualCandidateSource
	app      *App
	store    *config.Store
	config   config.Config
	service  catalog.Service
	lifetime context.Context
	job      *nodeCheckJob
	nodes    []string // frozen once, from the actual eligible fetch result
	frozen   bool
}

// Caller holds nodeChecks.mu while publishing the original accepted job.
func (a *App) legacyManualCandidateSource(ctx context.Context, service catalog.Service) *legacyManualCandidateSource {
	if a.Store == nil || a.nodeChecks.job == nil || ctx == nil || ctx.Err() != nil {
		return nil
	}
	s := &legacyManualCandidateSource{app: a, store: a.Store, config: a.Store.Get(), service: defaultRouteCloneCatalogService(service), lifetime: ctx, job: a.nodeChecks.job}
	s.self = s
	return s
}

func (s *legacyManualCandidateSource) current(a *App) error {
	if s == nil || s.self != s || s.app != a || s.store != a.Store || s.lifetime == nil || s.lifetime.Err() != nil {
		return dataplane.ErrNodeResourceDenied
	}
	a.nodeChecks.mu.Lock()
	current := a.nodeChecks.job == s.job && s.job.ID != 0 && s.job.Mode == "service" && s.job.ServiceID == s.service.ID && s.job.State == "running"
	a.nodeChecks.mu.Unlock()
	if !current || !reflect.DeepEqual(s.config, a.Store.Get()) || !a.nodeCheckDefinitionCurrent(s.service.ID, applyReviewHash(s.service)) {
		return errors.Join(dataplane.ErrNodeResourceDenied, config.ErrRevisionChanged)
	}
	return nil
}

// Called once by the same serial queue after source import and selection.
func (s *legacyManualCandidateSource) freeze(a *App, ids []string) error {
	if err := s.current(a); err != nil {
		return err
	}
	if s.frozen {
		return dataplane.ErrNodeResourceDenied
	}
	s.nodes, s.frozen = slices.Clone(ids), true
	return nil
}

func (a *App) legacyManualCandidateContext(ctx context.Context, source *legacyManualCandidateSource, service catalog.Service, nodeID string) (context.Context, func(), error) {
	if err := source.current(a); err != nil {
		return nil, nil, err
	}
	if ctx == nil || ctx.Err() != nil || !source.frozen || !slices.Contains(source.nodes, nodeID) || !reflect.DeepEqual(source.service, service) {
		return nil, nil, dataplane.ErrNodeResourceDenied
	}
	if err := a.Operations.WithExclusiveContext(ctx, func() error { return ctx.Err() }); err != nil {
		return nil, nil, errors.Join(dataplane.ErrNodeResourceDenied, err)
	}
	return a.issueManualNodeCandidate(ctx, source.config, service, []string{nodeID}, source)
}
