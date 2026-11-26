package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type mihomoNodeBindingKey struct{}

func mihomoNodeCatalogClone(in catalog.Catalog) catalog.Catalog {
	out := catalog.Catalog{}
	if in.Services != nil {
		out.Services = make([]catalog.Service, len(in.Services))
		for i, service := range in.Services {
			out.Services[i] = defaultRouteCloneCatalogService(service)
		}
	}
	return out
}

type mihomoNodeBinding struct {
	self    *mihomoNodeBinding
	app     *App
	store   *config.Store
	node    *dataplane.NodeDefaultSourceReview
	before  config.Config
	after   atomic.Pointer[config.Config]
	catalog catalog.Catalog
	plan    dataplane.Plan
	service catalog.Service
	profile string
}

func (b *mihomoNodeBinding) current(ctx context.Context) error {
	if b == nil || b.self != b || b.app == nil || b.store == nil || b.app.Store != b.store || b.node == nil || !reflect.DeepEqual(b.catalog, b.app.catalogSnapshot()) {
		return dataplane.ErrReviewChanged
	}
	expected := &b.before
	if after := b.after.Load(); after != nil {
		expected = after
	}
	if !reflect.DeepEqual(b.store.Get(), *expected) {
		return config.ErrRevisionChanged
	}
	actual, err := b.app.freshNetworkProfile(ctx)
	if err != nil || actual != b.profile {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	if err = b.node.Current(ctx); err != nil {
		return err
	}
	return b.app.nodeResourceExclusionAdmission(ctx, *expected, b.service, "", netip.Addr{})
}
func (b *mihomoNodeBinding) resource(ctx context.Context, a *App, plan dataplane.Plan, host string, address netip.Addr) error {
	if b == nil || b.self != b || b.app != a || b.plan.Digest != plan.Digest || b.plan.Revision != plan.Revision || !reflect.DeepEqual(b.plan.Routes, plan.Routes) || plan.Revision != b.before.Revision+1 {
		return dataplane.ErrReviewChanged
	}
	if err := b.current(ctx); err != nil {
		return err
	}
	expected := &b.before
	if after := b.after.Load(); after != nil {
		expected = after
	}
	return a.nodeResourceExclusionAdmission(ctx, *expected, b.service, host, address)
}

func (b *mihomoNodeBinding) commit(ctx context.Context) (func() error, error) {
	if b == nil || b.self != b || b.node == nil || ctx == nil || ctx.Value(mihomoNodeBindingKey{}) != b || len(b.plan.Routes) != 1 || b.plan.Routes[0].ServiceID != b.service.ID {
		return nil, dataplane.ErrReviewChanged
	}
	ref, route := b.node.Reference(), b.plan.Routes[0]
	if ref.EngineID != "mihomo" || ref.Resolved != "mihomo:"+ref.NodeID || route.Selected != ref.Resolved || route.Resolved != ref.Resolved || route.LogicalServiceID != b.service.ID {
		return nil, dataplane.ErrReviewChanged
	}
	if err := b.resource(ctx, b.app, b.plan, "", netip.Addr{}); err != nil {
		return nil, err
	}
	image, undo, err := b.store.ApplyMihomoNodeRouteScopeWithImage(b.service.ID, ref.NodeID, route.Sources, b.before.Revision)
	if err != nil {
		return nil, err
	}
	b.after.Store(&image)
	return func() error {
		err := undo()
		if err == nil {
			b.after.Store(nil)
		}
		return err
	}, nil
}
