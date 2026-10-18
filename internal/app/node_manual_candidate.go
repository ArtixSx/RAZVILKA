package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type manualNodeCandidateKey struct{}

// Original per-step diagnostic intent, never activation or client authority.
// Only the accepted durable node-check worker issues it under its own lease.
type manualNodeCandidate struct {
	self     *manualNodeCandidate
	mu       sync.Mutex
	active   bool
	app      *App
	store    *config.Store
	config   config.Config
	service  catalog.Service
	nodes    []string
	lifetime context.Context
}

func (a *App) manualNodeCandidateContext(ctx context.Context, request serviceControlJobRequest, cfg config.Config, service catalog.Service) (context.Context, func(), error) {
	if ctx == nil || ctx.Done() == nil || a.Store == nil || request.Kind != "node-check" || request.NodeCheckMode != "service" || request.durableID == 0 ||
		!validDurableNodeCheck(request) || len(request.ServiceIDs) != 1 || request.ServiceIDs[0] != service.ID ||
		cfg.Revision != *request.ExpectedRevision || request.intentHash != durableServiceIntentHash(cfg, []catalog.Service{service}) ||
		!reflect.DeepEqual(cfg, a.Store.Get()) || !a.nodeCheckDefinitionCurrent(service.ID, applyReviewHash(service)) {
		return nil, nil, dataplane.ErrNodeResourceDenied
	}
	if err := a.Operations.WithExclusiveContext(ctx, func() error { return ctx.Err() }); err != nil {
		return nil, nil, errors.Join(dataplane.ErrNodeResourceDenied, err)
	}
	intent := &manualNodeCandidate{active: true, app: a, store: a.Store, config: cfg, service: defaultRouteCloneCatalogService(service), nodes: slices.Clone(request.NodeIDs), lifetime: ctx}
	intent.self = intent
	return context.WithValue(ctx, manualNodeCandidateKey{}, intent), func() {
		intent.mu.Lock()
		intent.active = false
		intent.mu.Unlock()
	}, nil
}

func (a *App) nodeCandidateResourceAdmission(ctx context.Context, expected config.Config, service catalog.Service, nodeID, host string, address netip.Addr) error {
	if ctx == nil {
		return dataplane.ErrNodeResourceDenied
	}
	intent, _ := ctx.Value(manualNodeCandidateKey{}).(*manualNodeCandidate)
	if intent == nil {
		return a.nodeResourceAdmission(ctx, expected, service, host, address)
	}
	if intent.self != intent {
		return dataplane.ErrNodeResourceDenied
	}
	intent.mu.Lock()
	defer intent.mu.Unlock()
	if !intent.active || intent.app != a || intent.store != a.Store || intent.lifetime.Err() != nil || ctx.Err() != nil ||
		!reflect.DeepEqual(intent.config, expected) || !reflect.DeepEqual(intent.service, service) || !slices.Contains(intent.nodes, nodeID) {
		return dataplane.ErrNodeResourceDenied
	}
	if err := a.Operations.WithExclusiveContext(intent.lifetime, func() error { return ctx.Err() }); err != nil {
		return errors.Join(dataplane.ErrNodeResourceDenied, err)
	}
	// The same full config/disk image and every service/domain/address negative
	// still close before DNS, runtime effects and recording. Enabled is not
	// routing consent here: this exact explicit job only diagnoses a candidate.
	return a.nodeResourceExclusionAdmission(ctx, expected, service, host, address)
}
