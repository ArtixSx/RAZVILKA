package dataplane

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/components"
)

type nfqwsInitialInstallSource struct {
	manager *Manager
	adapter *NFQWS2Adapter
	owner   *components.Manager
}

// Uses the SAME startup-bound inactivity source; no second Bind, reconstructed
// process DTO, shell status, or detached kernel inventory can authorize install.
func (s *nfqwsInitialInstallSource) WithInitialNFQWSInstall(ctx context.Context, effect func(context.Context, func(context.Context) error) error) error {
	if s == nil || s.manager == nil || s.adapter == nil || s.owner == nil || ctx == nil || effect == nil {
		return components.ErrNFQWSInitialInstall
	}
	m, a := s.manager, s.adapter
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	check := func(c context.Context) error {
		current, ok := m.adapter("nfqws2")
		if !ok || current != a || a.stockNativeOwner != s.owner || a.InitPath != filepath.Join(s.owner.InitDir, "S51nfqws2") || a.ConfigPath != filepath.Join(filepath.Dir(s.owner.InitDir), "nfqws2", "nfqws2.conf") {
			return components.ErrNFQWSInitialInstall
		}
		lease, err := a.readLease()
		if err != nil || lease != nil {
			return errors.Join(components.ErrNFQWSInitialInstall, err)
		}
		if err := m.CheckExecutionRecovery(c); err != nil {
			return err
		}
		return a.VerifyRuntimeInactive(c)
	}
	if err := check(ctx); err != nil {
		return err
	}
	// The package changes formerly absent files, so fresh complete observations
	// are repeated inside the callback. No pre-install file image is reused.
	return effect(ctx, check)
}
