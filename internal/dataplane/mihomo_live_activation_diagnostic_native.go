//go:build razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"fmt"
)

// Fixed phase identifiers only. Never print an error string, path or material.
// Each call returns the original error unchanged, including errors.Join inputs.
func mihomoLiveActivationDiagnostic(stage string, err error) error {
	switch stage {
	case "phase-owner", "source-current", "native-current", "compiled-current", "forwarding", "candidate-policy", "engine-image", "sidecar-image", "publish-engine", "publish-sidecar", "sidecar-start", "policy-intent", "policy-apply", "source-closing", "policy-ack",
		"sidecar-source", "sidecar-native", "sidecar-compiled", "sidecar-construct", "sidecar-validate", "sidecar-pending", "sidecar-tun", "sidecar-observe", "sidecar-bound", "sidecar-child-exited", "sidecar-metadata", "sidecar-control", "sidecar-kernel":
		fmt.Printf("actual_mihomo_activate stage=%s failed=%t material=%t canceled=%t deadline=%t\n", stage, err != nil, errors.Is(err, errMihomoLiveMaterial), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
	}
	return err
}
