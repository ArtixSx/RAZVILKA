//go:build !linux

package dataplane

import "os"

func openWGInactivityObservationFile(path string) (*os.File, error) { return os.Open(path) }
