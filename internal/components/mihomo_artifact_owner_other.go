//go:build !linux

package components

import "os"

func mihomoInstalledOwner(os.FileInfo) bool { return false }

func mihomoArtifactOwner(os.FileInfo) bool  { return false }
func mihomoFileIdentity(os.FileInfo) string { return "" }
