//go:build !linux

package dataplane

import "os"

// Production process capture refuses outside Linux. This path keeps ordinary
// platform builds and private Windows transaction models available.
func retainedSingOpenFlags(write bool) int {
	if write {
		return os.O_RDWR
	}
	return os.O_RDONLY
}
