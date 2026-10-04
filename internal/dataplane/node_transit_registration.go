package dataplane

import "context"

// Only Manager installs this key while holding its operation/admission scope.
// Allocating a root alone grants no kernel effect: register must durably record
// the full typed spec and digest in the existing execution before receipt add.
type nodeTransitRegistrarKey struct{}

// Only lease.Remove sets this marker for its existing-record registration.
// It distinguishes held-scope cleanup from a forward Apply retry; it grants
// no authority without the issuer's original matching execution resource.
type nodeTransitRemovalKey struct{}

type nodeTransitRegistrar func(context.Context, NodeTransitSpec) (nodeTransitRegistration, error)

type nodeTransitRegistration struct {
	root     string
	register func(context.Context, NodeTransitSpec, string, string) error
	settle   func(context.Context, NodeTransitSpec, string, string) error
	// Optional only on a newly issued live resource. This settles Manager
	// metadata after the issuer consumes the original successful live proof
	// through its private context closure; it conveys no kernel deletion authority.
	settleUnused func(context.Context, NodeTransitSpec, string, string) error
	cleanupGuard func(context.Context) error
}
