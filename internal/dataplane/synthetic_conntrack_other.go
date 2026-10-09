//go:build !linux

package dataplane

import "context"

func readSyntheticConntrack(context.Context) (syntheticCTImage, error) {
	return syntheticCTImage{}, errSyntheticConntrack
}
