package app

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/sources"
)

// Detached comparison metadata distinguishes an actual locally applied custom
// definition from external source-cache provenance. Neither is a runtime grant.
type XrayListInlineSourceObservation struct {
	ServiceID     string
	CIDRs         []string
	CatalogSHA256 string
}

type xrayListInlineSource struct {
	self    *xrayListInlineSource
	source  *XrayListRuntimeSource
	manager *customservices.Manager
	review  *customservices.InlineCIDRReview
}

func (r *XrayListRuntimeSource) reviewDestinations(ctx context.Context) error {
	if !xrayListLiteralProbeInCIDRs(r.frozen) || r.cidrs != nil || r.inline != nil || r.control == nil || r.control.Current(ctx) != nil {
		return ErrXrayListSource
	}
	if len(r.frozen.SourceRefs) != 0 {
		var err error
		r.cidrs, err = r.sources.ReviewServiceCIDRs(ctx, r.service, r.frozen.SourceRefs)
		if err != nil {
			return err
		}
		observation, err := r.cidrs.Observation(ctx)
		if err != nil || !slices.Equal(r.frozen.CIDRs, observation.CIDRs) {
			return errors.Join(ErrXrayListSource, err)
		}
		return r.control.Current(ctx)
	}
	if r.custom == nil || r.app.CustomServices != r.custom || r.commitOwnersCurrent() != nil {
		return ErrXrayListSource
	}
	review, err := r.custom.ReviewAppliedInlineCIDRs(ctx, r.frozen)
	if err != nil {
		return errors.Join(ErrXrayListSource, err)
	}
	r.inline = &xrayListInlineSource{source: r, manager: r.custom, review: review}
	r.inline.self = r.inline
	return r.currentDestinations(ctx)
}

func (r *XrayListRuntimeSource) currentDestinations(ctx context.Context) error {
	if (r.cidrs == nil) == (r.inline == nil) {
		return ErrXrayListSource
	}
	if r.cidrs != nil {
		if len(r.frozen.SourceRefs) == 0 {
			return ErrXrayListSource
		}
		return r.cidrs.Current(ctx)
	}
	i := r.inline
	if i.self != i || i.source != r || i.manager != r.custom || r.app.CustomServices != i.manager || i.review == nil ||
		len(r.frozen.SourceRefs) != 0 || r.control == nil || r.commitOwnersCurrent() != nil || r.control.Current(ctx) != nil {
		return ErrXrayListSource
	}
	if err := i.review.Current(ctx, i.manager); err != nil {
		return errors.Join(ErrXrayListSource, err)
	}
	service := i.review.Service()
	frozen, err := dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: r.service, ProbeService: &service, ProbeURL: service.ProbeURL})
	if err != nil || !reflect.DeepEqual(frozen, r.frozen) || r.commitOwnersCurrent() != nil {
		return ErrXrayListSource
	}
	return r.control.Current(ctx)
}

func (r *XrayListRuntimeSource) destinationObservation(ctx context.Context) (sources.ServiceCIDRObservation, *XrayListInlineSourceObservation, error) {
	if err := r.currentDestinations(ctx); err != nil {
		return sources.ServiceCIDRObservation{}, nil, err
	}
	if r.cidrs != nil {
		o, err := r.cidrs.Observation(ctx)
		return o, nil, err
	}
	o := &XrayListInlineSourceObservation{ServiceID: r.service, CIDRs: slices.Clone(r.inline.review.Service().CIDRs), CatalogSHA256: r.catalog}
	return sources.ServiceCIDRObservation{}, o, r.currentDestinations(ctx)
}
