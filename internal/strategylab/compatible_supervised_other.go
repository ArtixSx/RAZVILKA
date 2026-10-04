//go:build !linux

package strategylab

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/components"
)

func compatibilityPrivateStateParent(string) error {
	return components.ErrNFQWSSupervisionUnavailable
}

func compatibilityLaunchSupervisor(context.Context, string, compatibilityReview, string, []string) (components.NFQWSSupervisionIdentity, error) {
	return components.NFQWSSupervisionIdentity{}, components.ErrNFQWSSupervisionUnavailable
}

// Only the Linux early CORE dispatch can run the private helper.
func RunCompatibilitySupervisor(string, string, string) int { return 1 }
