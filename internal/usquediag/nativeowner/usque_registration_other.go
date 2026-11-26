//go:build !linux

package nativeowner

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func PrepareUSQUEInitial(context.Context, *operationgate.Gate, USQUERegistrationBinding) (USQUERegistrationResult, error) {
	return USQUERegistrationResult{}, ErrUSQUERegistrationUnsupported
}
