//go:build !linux

package strategylab

import "errors"

func compatibilityProtectedPath(path string, allowMissingFile bool) error {
	return errors.New("compatibility protected paths require Linux ownership proof")
}
