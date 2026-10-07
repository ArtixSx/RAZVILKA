// Package nativeowner owns a real, one-use Linux USQUE child and its dedicated
// supervisor. Original operation/review/control authority is supplied by CORE;
// this owner never acquires authority from a PID, receipt or serialized binding.
package nativeowner

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

var ErrOwned = errors.New("native-usque-original-owner-required-or-unsettled")

type HelperAsset struct{ Path, SHA256 string }
type Namespace struct{ Device, Inode uint64 }

// Scope is factual input from held kernel/file descriptors. These values are
// not a grant. CORE issues the private original lease under its actual exclusive
// operation context/current immutable review and protected control record.
type Scope struct {
	Acquisition nativeaccept.Acquisition
	Namespace   Namespace
	Parent      components.NFQWSRuntimeProcessIdentity
	Helper      HelperAsset
	Deadline    time.Time
}

type Control struct {
	Root, TransactionID, InstallationID string
	Sequence                            uint64
}

type OriginalFactory interface {
	Acquire(context.Context, Scope) (OriginalLease, error)
}

// CORE keeps its actual same-gate exclusive lease live until Release. WithStart
// retains original asset review/close admission across the live child handshake;
// it is NOT the short control lock. WithEffectStart encloses only Cmd.Start.
// Current must be usable inside WithStart without reacquiring that close lock.
// Control is the original protected epoch, not caller metadata. Cleanup is bound
// to this same lease after cancellation; FenceUnsettled retains it on uncertainty.
type OriginalLease interface {
	Current(context.Context) error
	WithStart(context.Context, nativeaccept.Launch, func() error) error
	WithEffectStart(context.Context, string, func() error) error
	Control(context.Context) (Control, error)
	WithCleanup(context.Context, func() error) error
	Release(context.Context) error
	FenceUnsettled()
}

// ReviewBindingDigest is the exact typed wire binding for CORE's immutable
// review. It is factual binding only; a matching hash is never a lease issuer.
func ReviewBindingDigest(scope Scope, launch nativeaccept.Launch, control Control) string {
	return (offer{Version: 1, Scope: scope, Launch: cloneLaunch(launch), Control: control}).digest()
}

// NewIssuer constructs the concrete process owner. There is no registration
// hook/default permissive factory. The original CORE capability remains required.
func NewIssuer(original OriginalFactory, helper HelperAsset) (nativeaccept.Issuer, error) {
	if original == nil || !assetShape(helper) {
		return nil, ErrOwned
	}
	return &issuer{original: original, helper: helper, platform: nativePlatform()}, nil
}

// RunCoordinator is the executable coordinator entry after CORE obtains the
// actual original lease factory. It calls the genuine producer/readback runner.
// No account registration, route/namespace mutation or OSProcessController occurs.
func RunCoordinator(ctx context.Context, r nativeaccept.Request, helper HelperAsset, original OriginalFactory) nativeaccept.Result {
	owner, err := NewIssuer(original, helper)
	if err != nil {
		return nativeaccept.Result{Status: "blocked", Code: "core-original-lease-required", Settlement: "not-acquired", SecretCleanup: "not-staged"}
	}
	return nativeaccept.Run(ctx, r, owner)
}
