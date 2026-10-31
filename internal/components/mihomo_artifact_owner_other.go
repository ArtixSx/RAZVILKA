//go:build !linux

package components

import "os"

func mihomoArtifactOwner(os.FileInfo) bool { return false }
