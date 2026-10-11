package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This retained provider only classifies the actual fixed installer group.
// It cannot skip a PID or waive files, sockets, kernel or incarnation reads.
type scopedDNSInstallerRole struct {
	self     *scopedDNSInstallerRole
	adapter  *updatecheck.SelfUpdateFileAdapter
	id       string
	original context.Context
	deadline time.Time
	ordinary bool
}

// BindInstallerControllerRoles is trusted private-manager construction for a
// current self-update observer. There is no callback/role/skip-list argument;
// every relevant peer must pass the existing fixed OPS /proc+journal reader.
func (a *ScopedDNSAdapter) BindInstallerControllerRoles(ctx context.Context, adapter *updatecheck.SelfUpdateFileAdapter, id string) error {
	return a.bindInstallerControllerRoles(ctx, adapter, id, false)
}

// Ordinary roles use the distinct sealed controller-group reader. They never
// fall back to bootstrap classification after a missing or invalid proof.
func (a *ScopedDNSAdapter) BindOrdinaryInstallerControllerRoles(ctx context.Context, adapter *updatecheck.SelfUpdateFileAdapter, id string) error {
	return a.bindInstallerControllerRoles(ctx, adapter, id, true)
}

func (a *ScopedDNSAdapter) bindInstallerControllerRoles(ctx context.Context, adapter *updatecheck.SelfUpdateFileAdapter, id string, ordinary bool) error {
	if runtime.GOOS != "linux" || a == nil || adapter == nil || ctx == nil || ctx.Err() != nil || len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" ||
		a.StateRoot != filepath.Join(installpath.State+"/dataplane", scopedDNSAdapterID) {
		return ErrScopedDNSRuntimeInactive
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) {
		return ErrScopedDNSRuntimeInactive
	}
	if ordinary {
		if err := adapter.VerifyCurrentOrdinaryInstallerControllerRole(ctx, id); err != nil {
			return errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live != nil || a.installerRole != nil {
		return ErrScopedDNSRuntimeInactive
	}
	r := &scopedDNSInstallerRole{adapter: adapter, id: id, original: ctx, deadline: deadline, ordinary: ordinary}
	r.self = r
	a.installerRole = r
	return nil
}

func (r *scopedDNSInstallerRole) current(ctx context.Context) error {
	if r == nil || r.self != r || r.adapter == nil || r.original == nil || ctx == nil || ctx.Err() != nil || r.original.Err() != nil || !r.deadline.After(time.Now()) {
		return ErrScopedDNSRuntimeInactive
	}
	return nil
}

func (r *scopedDNSInstallerRole) check(ctx context.Context, pid int) error {
	if err := r.current(ctx); err != nil {
		return err
	}
	held, cancel := context.WithDeadline(ctx, r.deadline)
	stop := context.AfterFunc(r.original, cancel)
	defer cancel()
	defer stop()
	if r.ordinary {
		return errors.Join(r.adapter.VerifyOrdinaryInstallerControllerRole(held, r.id, pid), r.current(ctx))
	}
	return errors.Join(r.adapter.VerifyInstallerControllerRole(held, r.id, pid), r.current(ctx))
}

// These command names trigger a positive role check even when the recorded
// installer has a different filename/inode. They never establish the role.
func scopedDNSInstallerCommand(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[1] {
	case "self-update-bootstrap-old193", "self-update-command-helper", "self-update-runtime-quiesce":
		return true
	}
	return false
}
