package components

import (
	"context"
	"errors"
	"time"
)

var ErrComponentAlreadyInstalled = errors.New("component is already installed")

// InstallAbsent uses the ordinary package installer with an additional guard
// over a first install. Both a component and its missing dependency must still
// be absent immediately before the package command.
func (m *Manager) InstallAbsent(ctx context.Context, id string, guard func(context.Context) error) (Result, error) {
	if guard == nil || !supportsAutonomyInstall(id) {
		return Result{}, NoMutation(ErrRecoveryAuthority)
	}
	if err := guard(ctx); err != nil {
		return Result{}, NoMutation(err)
	}
	return m.apply(ctx, id, guard)
}

func supportsAutonomyInstall(id string) bool {
	return id == "sing-box" || id == "xray" || id == "warp-wg"
}

// RefreshInstallCatalog refreshes only existing Entware sources. A missing
// component does not authorize adding unrelated repositories or fetching
// release metadata for another component.
func (m *Manager) RefreshInstallCatalog(ctx context.Context, guard func(context.Context) error) error {
	if guard == nil || m.Opkg == "" {
		return NoMutation(ErrRecoveryAuthority)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.fencePackageMutation()
	if err != nil {
		return NoMutation(err)
	}
	defer release()
	if err := guard(ctx); err != nil {
		return NoMutation(err)
	}
	if m.refreshPackageCatalog(ctx, nil) {
		m.catalog = catalogStatus{CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	return ctx.Err()
}

func checkAbsentInstallation(ctx context.Context, installedVersion string, guard func(context.Context) error) error {
	if installedVersion != "" {
		return NoMutation(ErrComponentAlreadyInstalled)
	}
	if err := guard(ctx); err != nil {
		return NoMutation(err)
	}
	return nil
}

// LastInstallAttempt reads the existing operation receipt so a failed or
// interrupted preparation is paced across services and process restarts.
func (m *Manager) LastInstallAttempt(id string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// NFQWS2 and native MASQUE components have separate protected installers.
	if m.StateDir == "" || !supportsAutonomyInstall(id) && id != "nfqws2" && id != "usque" && id != MASQUESidecarComponent {
		return time.Time{}, ErrRecoveryAuthority
	}
	view := View{Spec: Spec{ID: id}}
	m.attachOperationStatus(&view)
	if view.OperationStatus == "receipt-error" {
		return time.Time{}, ErrRecoveryAuthority
	}
	if view.OperationAction != "install" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, view.OperationAt)
}
