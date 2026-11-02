//go:build !linux

package restorejournal

import "os"

func artifactReadFingerprint(os.FileInfo) (artifactReadFileID, error) {
	return artifactReadFileID{}, ErrUnavailable
}
