package app

import (
	"context"
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
)

// defaultRouteScopeAuthority is used by the trusted App constructor's observer.
// Only the original opaque reader can supply this comparison. Its Current
// checks remain outside Store observation and any long native start/transfer.
// The caller retains this SAME reader for bounded effect checks, exact shared
// CAS AcceptCommitted and joined Close; this helper issues no effect or path.
func defaultRouteScopeAuthority(ctx context.Context, store *config.Store, scope *defaultconsent.ScopeReview) (DefaultRouteAuthority, error) {
	if store == nil || scope == nil || !scope.MatchesConfigStore(store) {
		return DefaultRouteAuthority{}, errors.Join(ErrDefaultRouteCapability, defaultconsent.ErrChanged)
	}
	if err := scope.Current(ctx); err != nil {
		return DefaultRouteAuthority{}, errors.Join(ErrDefaultRouteCapability, err)
	}
	ref := scope.Reference()
	if !defaultRouteScopeReferenceValid(store.Get(), ref) {
		return DefaultRouteAuthority{}, errors.Join(ErrDefaultRouteCapability, defaultconsent.ErrChanged)
	}
	// Do not read Reference or call other reader methods from WithCurrent:
	// the opaque reader forbids reentry while a bounded use holds its lock.
	if err := scope.Current(ctx); err != nil {
		return DefaultRouteAuthority{}, errors.Join(ErrDefaultRouteCapability, err)
	}
	if !scope.MatchesConfigStore(store) {
		return DefaultRouteAuthority{}, errors.Join(ErrDefaultRouteCapability, defaultconsent.ErrChanged)
	}
	return ref, nil
}

// This is only definition validation. A detached, well-shaped reference never
// replaces the original ScopeReview/current control or selected source owner.
func defaultRouteScopeReferenceValid(cfg config.Config, ref DefaultRouteAuthority) bool {
	return cfg.NetworkPolicy != nil && ref.Schema == 1 &&
		len(ref.InstallationID) == 32 && strings.Trim(ref.InstallationID, "0123456789abcdef") == "" &&
		ref.Sequence != 0 && ref.ApprovalRevision != 0 && ref.ApprovalRevision <= cfg.Revision &&
		ref.PolicyRevision == cfg.NetworkPolicy.Revision && defaultRouteHash(ref.ConsentDigest) &&
		ref.EngineID == "" && ref.NodeID == "" && ref.Resolved == "" &&
		ref.NodeGeneration == 0 && ref.NodeMaterialSHA256 == ""
}
