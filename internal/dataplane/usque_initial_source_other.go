//go:build !linux

package dataplane

import "os"

const usqueLiveSessionReadFlags = os.O_RDONLY

func usqueInitialPrivateSession(os.FileInfo) bool { return false }

func usqueInitialProtectedPath(string) bool               { return false }
func usqueInitialSameOwner(os.FileInfo, os.FileInfo) bool { return false }
