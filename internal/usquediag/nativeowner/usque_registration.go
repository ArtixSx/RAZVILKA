package nativeowner

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

var (
	ErrUSQUERegistrationUnsupported = errors.New("USQUE registration requires an audited native executable")
	ErrUSQUERegistrationConsent     = errors.New("USQUE consumer registration is not authorized")
	ErrUSQUERegistrationChanged     = errors.New("USQUE registration admission changed")
	ErrUSQUERegistrationState       = errors.New("USQUE private registration state is unavailable or changed")
	ErrUSQUERegistrationBusy        = errors.New("USQUE private registration state has another writer")
	ErrUSQUERegistrationPending     = errors.New("USQUE registration or enrollment outcome is unknown")
	ErrUSQUERegistrationTimeout     = errors.New("USQUE registration exceeded its deadline")
	ErrUSQUERegistrationSession     = errors.New("USQUE registration did not produce a usable private session")
	ErrUSQUERegistrationSlot        = errors.New("USQUE session slot already has a different configuration")
)

// USQUERegistrationBinding is supplied by the original application owner.
// AcceptTOS and Review come from its current MASQUE policy, never HTTP input.
// ControlRoot is its existing protected installation owner. The attempt is
// stored there, with no independently selectable enrollment state path.
// The caller holds its original Gate until PrepareUSQUEInitial returns.
type USQUERegistrationBinding struct {
	ControlRoot          string
	Binary, BinarySHA256 string
	AcceptTOS            bool
	Configs              *engineconfig.Manager
	Review               func(context.Context) error
}

// USQUERegistrationResult reports only a staged configuration. The exact
// current service and effective path must still be checked by the Manager.
type USQUERegistrationResult struct {
	SHA256 string
	Reused bool
}
