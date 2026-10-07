//go:build !linux || (!amd64 && !arm64)

package netidentity

import "context"

func readObservation(context.Context) (observation, error) { return observation{}, ErrUnknown }
func readBuild(context.Context) (buildTuple, error)        { return buildTuple{}, ErrUnknown }
