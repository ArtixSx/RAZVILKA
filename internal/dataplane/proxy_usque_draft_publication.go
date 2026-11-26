package dataplane

import (
	"context"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type usqueDraftPublicationKey struct{}

type usqueDraftPublication struct {
	adapter *ProxyTunnelAdapter
	configs *engineconfig.Manager
	digest  string
	open    atomic.Bool
}

// ReviewingPublishedUSQUEDraft identifies only the original USQUE adapter's
// exact draft write inside its Commit. It is revoked before Commit returns.
// It cannot stand in for the Manager's final adapter/transaction commit.
func ReviewingPublishedUSQUEDraft(ctx context.Context, configs *engineconfig.Manager, digest string) bool {
	if ctx == nil || ctx.Err() != nil || configs == nil || digest == "" {
		return false
	}
	proof, _ := ctx.Value(usqueDraftPublicationKey{}).(*usqueDraftPublication)
	return proof != nil && proof.open.Load() && proof.adapter.ID() == "usque" && proof.adapter.Configs == configs &&
		proof.configs == configs && proof.digest == digest
}

func (a *ProxyTunnelAdapter) checkUSQUEDraftImage(snapshot proxySnapshot, source string) error {
	current, err := a.Configs.ReadExpert("usque", "main")
	if err != nil || current.Source != source || current.Path != snapshot.ConfigPath || current.SHA256 != routeidentity.Hash(snapshot.StagedConfig) {
		return ErrReviewChanged
	}
	return nil
}

func (a *ProxyTunnelAdapter) observePublishedUSQUEDraft(ctx context.Context, snapshot proxySnapshot) (context.Context, func(), error) {
	if err := a.checkUSQUEDraftImage(snapshot, "live"); err != nil {
		return nil, nil, err
	}
	proof := &usqueDraftPublication{adapter: a, configs: a.Configs, digest: routeidentity.Hash(snapshot.StagedConfig)}
	proof.open.Store(true)
	return context.WithValue(ctx, usqueDraftPublicationKey{}, proof), func() { proof.open.Store(false) }, nil
}
