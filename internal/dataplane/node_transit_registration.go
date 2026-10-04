package dataplane

import "context"

// Only Manager installs this key while holding its operation/admission scope.
// Allocating a root alone grants no kernel effect: register must durably record
// the full typed spec and digest in the existing execution before receipt add.
type nodeTransitRegistrarKey struct{}

type nodeTransitRegistrar func(context.Context, NodeTransitSpec) (nodeTransitRegistration, error)

type nodeTransitRegistration struct {
	root         string
	register     func(context.Context, NodeTransitSpec, string, string) error
	settle       func(context.Context, NodeTransitSpec, string, string) error
	cleanupGuard func(context.Context) error
}
