package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// WGSourceProfileCapture retains actual registered source bytes privately.
// Detached metadata is only comparison; no tool/path/traffic PASS is emitted.
type WGSourceProfileCapture struct {
	self                                             *WGSourceProfileCapture
	reader                                           *WGSourceReadReview
	profile, revision, content, digest, source, path string
}
type WGSourceProfileObservation struct{ EngineID, ProfileID, Revision, ContentSHA256 string }

func (*WGSourceProfileCapture) String() string { return "[private original WG source profile capture]" }
func (*WGSourceProfileCapture) GoString() string {
	return "[private original WG source profile capture]"
}

func (r *WGSourceReadReview) CaptureProfile(ctx context.Context, profile string) (*WGSourceProfileCapture, error) {
	if profile == "" {
		return nil, ErrWGOperationOwner
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	c := &WGSourceProfileCapture{reader: r, profile: profile}
	c.self = c
	if profile == "main" {
		if r.adapter.Configs == nil {
			return nil, ErrWGOperationOwner
		}
		value, err := r.adapter.Configs.ReadExpert(r.adapter.ID(), "main")
		if err != nil || value.Source != "live" || value.Content == "" {
			return nil, errors.Join(ErrWGOperationOwner, err)
		}
		c.content, c.source, c.path = value.Content, value.Source, value.Path
	} else {
		if r.adapter.ID() != "wireguard" || r.adapter.Profiles == nil {
			return nil, ErrWGOperationOwner
		}
		value, err := r.adapter.Profiles.Get(ctx, profile)
		if err != nil {
			return nil, errors.Join(ErrWGOperationOwner, err)
		}
		c.content, c.revision = value.Config(), value.Public().Revision
		c.source = "registered named profile"
	}
	if r.adapter.ID() == "wireguard" {
		if _, err := awgprofile.ParsePlainWireGuard(c.content); err != nil {
			return nil, errors.Join(ErrWGOperationOwner, err)
		}
	} else if _, err := awgprofile.Parse(c.content); err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	hash := sha256.Sum256([]byte(c.content))
	c.digest = hex.EncodeToString(hash[:])
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *WGSourceProfileCapture) Observation(ctx context.Context) (WGSourceProfileObservation, error) {
	if err := c.Current(ctx); err != nil {
		return WGSourceProfileObservation{}, err
	}
	return WGSourceProfileObservation{EngineID: c.reader.adapter.ID(), ProfileID: c.profile, Revision: c.revision, ContentSHA256: c.digest}, nil
}
func (c *WGSourceProfileCapture) Current(ctx context.Context) error {
	if c == nil || c.self != c || c.reader == nil {
		return ErrWGOperationOwner
	}
	actual, err := c.reader.CaptureProfile(ctx, c.profile)
	if err != nil || actual.content != c.content || actual.digest != c.digest || actual.revision != c.revision || actual.source != c.source || actual.path != c.path {
		return errors.Join(ErrWGOperationOwner, err)
	}
	return nil
}

// ObserveNumericEndpoint reuses the original endpoint/WAN parser. Numeric
// public addresses avoid granting selected-DNS consent or resolver callbacks.
// Only a SAME reader's actual captured profile can select this read target.
func (r *WGSourceReadReview) ObserveNumericEndpoint(ctx context.Context, capture *WGSourceProfileCapture) (WGEndpointState, error) {
	if capture == nil || capture.self != capture || capture.reader != r {
		return WGEndpointState{}, ErrWGOperationOwner
	}
	if err := capture.Current(ctx); err != nil {
		return WGEndpointState{}, err
	}
	endpoint, err := wgEndpoint(capture.content)
	if err != nil {
		return WGEndpointState{}, errors.Join(ErrWGOperationOwner, err)
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || address.Port() == 0 || address.String() != endpoint || !publicfetch.PublicAddress(address.Addr()) {
		return WGEndpointState{}, ErrWGOperationOwner
	}
	reader := *r.adapter
	reader.Runner, reader.Resolver, reader.EndpointResolver, reader.EndpointNow = r, nil, nil, nil
	_, wan, err := reader.stageWGEndpointForNetwork(ctx, capture.content, true)
	if err != nil || wan == nil {
		return WGEndpointState{}, errors.Join(ErrWGOperationOwner, err)
	}
	if err := capture.Current(ctx); err != nil {
		return WGEndpointState{}, err
	}
	return *wan, nil
}
