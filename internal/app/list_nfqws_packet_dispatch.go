package app

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Exactly one original purpose is retained. No nil/copy/composite can fall
// through to a more permissive scope; Close still releases both partial owners.
func (e *managedNFQWSListExecution) originalScope() bool {
	if e == nil || e.self != e || (e.scope == nil) == (e.packetScope == nil) {
		return false
	}
	if e.scope != nil {
		return e.scope.self == e.scope
	}
	return e.packetScope.self == e.packetScope
}
func (e *managedNFQWSListExecution) scopeCurrent(ctx context.Context, p *dataplane.LANPolicyRuntimePlan) error {
	if !e.originalScope() {
		return ErrListScopeChanged
	}
	if e.scope != nil {
		return e.scope.ScopeCheck(ctx, p)
	}
	return e.packetScope.ScopeCheck(ctx, p)
}
func (e *managedNFQWSListExecution) scopeCleanupCurrent(ctx context.Context, p *dataplane.LANPolicyRuntimePlan) error {
	if !e.originalScope() {
		return ErrListScopeChanged
	}
	if e.scope != nil {
		return e.scope.cleanupScopeCheck(ctx, p)
	}
	return e.packetScope.cleanupScopeCheck(ctx, p)
}
func (e *managedNFQWSListExecution) scopeAcceptCommitted(ctx context.Context, cfg config.Config, started, finished time.Time) error {
	if !e.originalScope() {
		return ErrListScopeChanged
	}
	if e.scope != nil {
		return e.scope.AcceptCommitted(ctx, cfg, started, finished)
	}
	return e.packetScope.AcceptCommitted(ctx, cfg, started, finished)
}
