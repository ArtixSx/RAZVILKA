//go:build !linux

package updatecheck

import "context"

func commitOfflinePriorReplacement(context.Context, *offlinePriorReplacement, func(func() error) error) error {
	return ErrFileProtocol
}
func renameOfflinePriorReplacement(*offlinePriorReplacement) error { return ErrFileProtocol }
